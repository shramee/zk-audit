package verifier

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Code is runtime bytecode with the ranges solc fills at deployment
// (immutables), which a comparison masks.
type Code struct {
	Bytes []byte
	// Masks are [start, start+length) ranges of immutable references.
	Masks [][2]int
	From  string
}

var reHex = regexp.MustCompile(`^(0x)?[0-9a-fA-F]*$`)

// ReadCode reads runtime bytecode from a file holding hex (with or without
// 0x, whitespace allowed) or a Foundry / solc artifact JSON
// (deployedBytecode.object and deployedBytecode.immutableReferences).
func ReadCode(path string) (*Code, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseCode(path, b)
}

// ParseCode parses hex or artifact JSON.
func ParseCode(from string, b []byte) (*Code, error) {
	t := strings.TrimSpace(string(b))
	if strings.HasPrefix(t, "{") {
		var art struct {
			DeployedBytecode json.RawMessage `json:"deployedBytecode"`
			EVM              *struct {
				DeployedBytecode json.RawMessage `json:"deployedBytecode"`
			} `json:"evm"`
		}
		if err := json.Unmarshal(b, &art); err != nil {
			return nil, fmt.Errorf("%s: %w", from, err)
		}
		raw := art.DeployedBytecode
		if raw == nil && art.EVM != nil {
			raw = art.EVM.DeployedBytecode
		}
		if raw == nil {
			return nil, fmt.Errorf("%s: no deployedBytecode in the artifact", from)
		}
		var obj struct {
			Object string `json:"object"`
			Refs   map[string][]struct {
				Start  int `json:"start"`
				Length int `json:"length"`
			} `json:"immutableReferences"`
		}
		var s string
		if json.Unmarshal(raw, &s) == nil {
			obj.Object = s
		} else if err := json.Unmarshal(raw, &obj); err != nil {
			return nil, fmt.Errorf("%s: deployedBytecode: %w", from, err)
		}
		c, err := ParseCode(from, []byte(obj.Object))
		if err != nil {
			return nil, err
		}
		for _, rs := range obj.Refs {
			for _, r := range rs {
				c.Masks = append(c.Masks, [2]int{r.Start, r.Length})
			}
		}
		return c, nil
	}
	t = strings.Join(strings.Fields(t), "")
	if !reHex.MatchString(t) {
		return nil, fmt.Errorf("%s: not hex bytecode or an artifact JSON", from)
	}
	t = strings.TrimPrefix(t, "0x")
	if strings.Contains(t, "__") {
		return nil, fmt.Errorf("%s: unlinked library placeholders in the bytecode", from)
	}
	raw, err := hex.DecodeString(t)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", from, err)
	}
	return &Code{Bytes: raw, From: from}, nil
}

// StripMetadata removes solc's CBOR metadata trailer (its length is in the
// last two bytes) and returns the code and the trailer.
func StripMetadata(code []byte) ([]byte, []byte) {
	if len(code) < 2 {
		return code, nil
	}
	n := int(code[len(code)-2])<<8 | int(code[len(code)-1])
	if n == 0 || n+2 > len(code) {
		return code, nil
	}
	start := len(code) - 2 - n
	// a CBOR map with 1 to 5 entries
	if code[start] < 0xa1 || code[start] > 0xa5 {
		return code, nil
	}
	return code[:start], code[start:]
}

// PushImmediates returns the values pushed by PUSH1..PUSH32 instructions
// (decoded linearly, so data after the code may add spurious values), as
// 0x-hex strings.
func PushImmediates(code []byte) map[string]bool {
	out := map[string]bool{}
	for i := 0; i < len(code); i++ {
		op := code[i]
		if op >= 0x60 && op <= 0x7f {
			n := int(op-0x60) + 1
			if i+1+n > len(code) {
				break
			}
			v := new(big.Int).SetBytes(code[i+1 : i+1+n])
			out["0x"+v.Text(16)] = true
			i += n
		}
	}
	return out
}

// BytecodeReport compares deployed with locally built runtime bytecode and
// looks for VK constants among the deployed code's PUSH immediates.
type BytecodeReport struct {
	Deployed string `json:"deployed"`
	Local    string `json:"local,omitempty"`
	// Match: equal (after stripping metadata and masking immutables),
	// metadata-only (only the metadata trailer differs), different.
	Match         string   `json:"match,omitempty"`
	DeployedSize  int      `json:"deployed_size"`
	LocalSize     int      `json:"local_size,omitempty"`
	FirstDiff     int      `json:"first_difference,omitempty"`
	Detail        string   `json:"detail,omitempty"`
	VKChecked     int      `json:"vk_constants_checked,omitempty"`
	VKFound       []string `json:"vk_constants_found,omitempty"`
	VKMissing     []string `json:"vk_constants_missing,omitempty"`
	VKExtractNote string   `json:"vk_note,omitempty"`
}

// CompareBytecode compares deployed with local code (local may be nil) and,
// when vk is non-empty, checks that every VK constant is pushed by the
// deployed code: the on-chain VK equals the source's when all are found.
func CompareBytecode(deployed, local *Code, vk []Constant) *BytecodeReport {
	r := &BytecodeReport{Deployed: deployed.From, DeployedSize: len(deployed.Bytes)}
	d, dm := StripMetadata(deployed.Bytes)
	if local != nil {
		r.Local, r.LocalSize = local.From, len(local.Bytes)
		l, lm := StripMetadata(local.Bytes)
		d2, l2 := mask(d, local.Masks), mask(l, local.Masks)
		switch {
		case bytes.Equal(d2, l2) && bytes.Equal(dm, lm):
			r.Match = "equal"
			r.Detail = "runtime bytecode is identical"
		case bytes.Equal(d2, l2):
			r.Match = "metadata-only"
			r.Detail = "runtime bytecode is identical apart from the metadata trailer (source file names, comments or compiler settings that do not change code)"
		default:
			r.Match = "different"
			r.FirstDiff = firstDiff(d2, l2)
			r.Detail = fmt.Sprintf("runtime bytecode differs from offset %d (deployed %d bytes, local %d bytes without metadata): another source, another compiler version or settings (optimizer runs, via-ir, evm version), or another VK", r.FirstDiff, len(d2), len(l2))
		}
	}
	if len(vk) > 0 {
		push := PushImmediates(d)
		for _, c := range vk {
			r.VKChecked++
			if push[c.Value] {
				r.VKFound = append(r.VKFound, c.Name)
			} else {
				r.VKMissing = append(r.VKMissing, c.Name)
			}
		}
		sort.Strings(r.VKFound)
		sort.Strings(r.VKMissing)
		switch {
		case len(r.VKMissing) == 0:
			r.VKExtractNote = "every VK constant of the source is pushed by the deployed code: the on-chain VK is the source's"
		case len(r.VKFound) == 0:
			r.VKExtractNote = "no VK constant of the source is in the deployed code: the deployed verifier has another VK (or another curve or template)"
		default:
			r.VKExtractNote = "some VK constants are missing from the deployed code's PUSH immediates: the VK differs, or the optimizer folded those constants; compare with a local build"
		}
	}
	return r
}

func mask(code []byte, ms [][2]int) []byte {
	if len(ms) == 0 {
		return code
	}
	out := append([]byte{}, code...)
	for _, m := range ms {
		for i := m[0]; i < m[0]+m[1] && i < len(out); i++ {
			out[i] = 0
		}
	}
	return out
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

// FetchCode reads an address's runtime bytecode with eth_getCode. It is the
// one network call of the verifier commands and runs only when the user
// passed --rpc.
func FetchCode(ctx context.Context, rpc, address, block string) (*Code, error) {
	if !regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`).MatchString(address) {
		return nil, fmt.Errorf("address %q is not a 0x-prefixed 20-byte hex address", address)
	}
	if block == "" {
		block = "latest"
	}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_getCode", "params": []string{address, block}})
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rpc, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	var out struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("eth_getCode: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("eth_getCode: %s", out.Error.Message)
	}
	if out.Result == "" || out.Result == "0x" {
		return nil, fmt.Errorf("eth_getCode: no code at %s (%s)", address, block)
	}
	return ParseCode(address+"@"+block, []byte(out.Result))
}
