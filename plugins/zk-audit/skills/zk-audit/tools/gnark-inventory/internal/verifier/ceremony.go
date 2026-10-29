package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
)

// SetupCall is a Go call that makes or checks proving and verifying keys.
type SetupCall struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Call string `json:"call"`
	// Kind: single-party (groth16.Setup, plonk.Setup), unsafe-srs
	// (unsafekzg.NewSRS, kzg.NewSRS with a chosen secret), mpc (mpcsetup:
	// phase initialisation, contribution, verification, sealing).
	Kind   string `json:"kind"`
	InTest bool   `json:"in_test_file"`
}

// Artifact is a key or ceremony file in the repository.
type Artifact struct {
	File   string `json:"file"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256,omitempty"`
	// Kind: snarkjs-zkey, snarkjs-ptau, gnark-mpc-phase1, gnark-mpc-phase2,
	// verifying-key, proving-key, srs, ceremony-file.
	Kind string `json:"kind"`
	// Contributions is the contribution count read from the file (snarkjs
	// zkey and ptau record it), -1 when the format does not record it.
	Contributions int    `json:"contributions"`
	Detail        string `json:"detail,omitempty"`
}

// Ceremony is what the repository shows about how its keys were made.
type Ceremony struct {
	Setups    []SetupCall `json:"setup_calls"`
	Artifacts []Artifact  `json:"artifacts"`
	// Verdict: single-party, mpc, keys-without-provenance, none.
	Verdict string `json:"verdict"`
	Detail  string `json:"detail"`
}

var setupPatterns = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`\b(groth16|plonk)\s*\.\s*Setup\s*\(`), "single-party"},
	{regexp.MustCompile(`\bunsafekzg\s*\.\s*NewSRS\s*\(`), "unsafe-srs"},
	{regexp.MustCompile(`\bkzg\s*\.\s*NewSRS\s*\(`), "unsafe-srs"},
	{regexp.MustCompile(`\bmpcsetup\s*\.\s*([A-Z]\w*)\s*\(`), "mpc"},
	{regexp.MustCompile(`\.\s*(Contribute|Seal|Initialize)\s*\(`), "mpc"},
}

// ScanCeremony lists key-generation calls in the Go sources and key or
// ceremony files under root, and reads the contribution count where the
// file format records it.
func ScanCeremony(root string) (*Ceremony, error) {
	c := &Ceremony{Setups: []SetupCall{}, Artifacts: []Artifact{}}
	files, err := fsutil.Walk(root, nil)
	if err != nil {
		return nil, err
	}
	usesMPC := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f.Rel, ".go") {
			b, err := os.ReadFile(f.Abs)
			if err != nil {
				continue
			}
			src := string(b)
			mpcFile := strings.Contains(src, "/mpcsetup\"")
			usesMPC[f.Rel] = mpcFile
			lines := strings.Split(src, "\n")
			for i, ln := range lines {
				code := ln
				if j := strings.Index(code, "//"); j >= 0 {
					code = code[:j]
				}
				for _, p := range setupPatterns {
					m := p.re.FindString(code)
					if m == "" {
						continue
					}
					if p.kind == "mpc" && !mpcFile {
						continue
					}
					c.Setups = append(c.Setups, SetupCall{File: f.Rel, Line: i + 1, Call: strings.TrimSpace(code), Kind: p.kind,
						InTest: strings.HasSuffix(f.Rel, "_test.go")})
					break
				}
			}
			continue
		}
		if a, ok := artifactOf(f); ok {
			c.Artifacts = append(c.Artifacts, a)
		}
	}
	c.judge()
	return c, nil
}

var (
	reKeyName = regexp.MustCompile(`(?i)(^|[._/-])(vk|pk|verifying[._-]?key|proving[._-]?key|vkey|zkey)([._-]|$)`)
	reMPCName = regexp.MustCompile(`(?i)(phase[._-]?1|phase[._-]?2|ph1|ph2|contribution|transcript|ceremony|beacon)`)
)

// artifactOf classifies a non-Go file by name and magic bytes.
func artifactOf(f fsutil.File) (Artifact, bool) {
	base := strings.ToLower(path.Base(f.Rel))
	ext := path.Ext(base)
	switch ext {
	case ".go", ".sol", ".md", ".txt", ".json", ".toml", ".yaml", ".yml", ".mod", ".sum", ".sh", ".ts", ".js", ".rs", ".py", ".circom", ".nr", ".lock", ".html", ".css":
		// sources and docs are not key material (snarkjs verification_key.json
		// is listed below by name)
		if !(ext == ".json" && reKeyName.MatchString(base)) {
			return Artifact{}, false
		}
	}
	a := Artifact{File: f.Rel, Contributions: -1}
	switch {
	case ext == ".zkey":
		a.Kind = "snarkjs-zkey"
	case ext == ".ptau":
		a.Kind = "snarkjs-ptau"
	case ext == ".srs" || strings.Contains(base, "srs"):
		a.Kind = "srs"
	case reMPCName.MatchString(base):
		switch {
		case strings.Contains(base, "1"):
			a.Kind = "gnark-mpc-phase1"
		case strings.Contains(base, "2"):
			a.Kind = "gnark-mpc-phase2"
		default:
			a.Kind = "ceremony-file"
		}
	case ext == ".vk" || strings.Contains(base, "verifying") || strings.Contains(base, "vkey") || reKeyName.MatchString(base) && strings.Contains(base, "vk"):
		a.Kind = "verifying-key"
	case ext == ".pk" || strings.Contains(base, "proving") || reKeyName.MatchString(base) && strings.Contains(base, "pk"):
		a.Kind = "proving-key"
	default:
		return Artifact{}, false
	}
	st, err := os.Stat(f.Abs)
	if err != nil {
		return Artifact{}, false
	}
	a.Size = st.Size()
	fh, err := os.Open(f.Abs)
	if err != nil {
		return a, true
	}
	defer fh.Close()
	if a.Size <= 64<<20 {
		h := sha256.New()
		if _, err := io.Copy(h, fh); err == nil {
			a.SHA256 = hex.EncodeToString(h.Sum(nil))
		}
	} else {
		a.Detail = "larger than 64 MiB: not hashed"
	}
	switch a.Kind {
	case "snarkjs-zkey":
		a.Contributions, a.Detail = binSectionCount(f.Abs, "zkey", 10, 64)
	case "snarkjs-ptau":
		a.Contributions, a.Detail = binSectionCount(f.Abs, "ptau", 7, 0)
	}
	return a, true
}

// binSectionCount reads a snarkjs binary file (magic, version, sections of
// type uint32 + size uint64) and returns the uint32 at offset skip of the
// section of the given type: the contribution count of a zkey (section 10,
// after the 64-byte circuit hash) or a ptau (section 7).
func binSectionCount(file, magic string, section uint32, skip int64) (int, string) {
	f, err := os.Open(file)
	if err != nil {
		return -1, err.Error()
	}
	defer f.Close()
	var head [12]byte
	if _, err := io.ReadFull(f, head[:]); err != nil || !bytes.Equal(head[:4], []byte(magic)) {
		return -1, "not a snarkjs " + magic + " file (magic bytes differ)"
	}
	n := binary.LittleEndian.Uint32(head[8:12])
	off := int64(12)
	for i := uint32(0); i < n && i < 64; i++ {
		var sh [12]byte
		if _, err := f.ReadAt(sh[:], off); err != nil {
			return -1, "truncated section table"
		}
		typ := binary.LittleEndian.Uint32(sh[:4])
		size := int64(binary.LittleEndian.Uint64(sh[4:12]))
		if typ == section {
			var cnt [4]byte
			if _, err := f.ReadAt(cnt[:], off+12+skip); err != nil {
				return -1, "truncated contributions section"
			}
			return int(binary.LittleEndian.Uint32(cnt[:])), fmt.Sprintf("section %d records the contributions", section)
		}
		off += 12 + size
	}
	return 0, fmt.Sprintf("no contributions section (%d): no contribution after the initial setup", section)
}

func (c *Ceremony) judge() {
	var single, mpc, srs []string
	for _, s := range c.Setups {
		if s.InTest {
			continue
		}
		at := fmt.Sprintf("%s:%d", s.File, s.Line)
		switch s.Kind {
		case "single-party":
			single = append(single, at)
		case "mpc":
			mpc = append(mpc, at)
		case "unsafe-srs":
			srs = append(srs, at)
		}
	}
	sort.Strings(single)
	contrib := []string{}
	for _, a := range c.Artifacts {
		switch {
		case a.Contributions >= 0:
			contrib = append(contrib, fmt.Sprintf("%s: %d contribution(s)", a.File, a.Contributions))
		case a.Kind == "gnark-mpc-phase2" || a.Kind == "gnark-mpc-phase1":
			contrib = append(contrib, a.File+": one gnark mpcsetup state (gnark records no count; count the files of each phase)")
		}
	}
	switch {
	case len(mpc) > 0:
		c.Verdict = "mpc"
		c.Detail = fmt.Sprintf("mpcsetup calls at %s", strings.Join(mpc, ", "))
		if len(single) > 0 {
			c.Detail += fmt.Sprintf("; a single-party setup also runs at %s: find out which keys are deployed", strings.Join(single, ", "))
		}
	case len(single) > 0 || len(srs) > 0:
		c.Verdict = "single-party"
		c.Detail = "keys come from a single-party setup at " + strings.Join(append(single, srs...), ", ") +
			" outside tests, and the repository has no MPC ceremony code: whoever ran it could keep the toxic waste and forge proofs, unless the deployed keys come from elsewhere"
	case len(c.Artifacts) > 0:
		c.Verdict = "keys-without-provenance"
		c.Detail = "key or ceremony files without the code or transcript that made them: ask how they were generated"
	default:
		c.Verdict = "none"
		c.Detail = "no key-generation code and no key or ceremony files in the repository: the deployed keys' provenance is outside it"
	}
	if len(contrib) > 0 {
		c.Detail += "; " + strings.Join(contrib, "; ")
	}
}
