package verifier

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fixture"
)

func readFixture(t *testing.T, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{fixture.Dir(t, "sol-gnark-abi")}, parts...)...))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestConstantsOfAGnarkVerifier(t *testing.T) {
	src := readFixture(t, "contracts", "Verifier.sol")
	vk := VKConstants(src)
	names := map[string]bool{}
	for _, c := range vk {
		names[c.Name] = true
	}
	// alpha (2), beta, gamma, delta (4 each), constant (2), 2 public inputs (4)
	if len(vk) != 20 || !names["ALPHA_X"] || !names["PUB_1_Y"] || !names["DELTA_NEG_Y_1"] {
		t.Fatalf("VK constants (%d): %v", len(vk), names)
	}
	for _, c := range Constants(src) {
		if (c.Name == "P" || c.Name == "R" || c.Name == "PRECOMPILE_VERIFY") && c.VK {
			t.Errorf("%s classified as VK", c.Name)
		}
	}
}

// A verifier with the same template and another setup differs only in VK;
// a hand edit shows as a structural difference.
func TestDiff(t *testing.T) {
	src := readFixture(t, "contracts", "Verifier.sol")
	same := Diff("a", src, "b", src)
	if !same.Structure.Equal || !same.VK.Equal || !strings.Contains(same.Summary, "same verifier") {
		t.Fatalf("self diff: %+v", same)
	}
	vk := VKConstants(src)
	other := strings.Replace(src, vk[0].Value[2:], "1234", 1)
	if other == src {
		// decimal constants: replace the decimal text instead
		other = strings.Replace(src, "ALPHA_X = ", "ALPHA_X = 1", 1)
	}
	fresh := Diff("committed", src, "regenerated", other)
	if !fresh.Structure.Equal || fresh.VK.Equal || len(fresh.VK.Changed) != 1 || !strings.Contains(fresh.Summary, "fresh setup") {
		t.Fatalf("VK-only diff: %+v", fresh)
	}
	edited := strings.Replace(src, "if (!success) {", "if (false) {", 1)
	if edited == src {
		t.Fatal("fixture no longer has the success check this test edits")
	}
	e := Diff("committed", src, "edited", edited)
	if e.Structure.Equal || e.Structure.CodeEqual || !e.VK.Equal {
		t.Fatalf("hand edit: %+v", e.Structure)
	}
}

func TestBytecode(t *testing.T) {
	hexCode := readFixture(t, "deployed", "Verifier.runtime.hex")
	dep, err := ParseCode("deployed", []byte(hexCode))
	if err != nil {
		t.Fatal(err)
	}
	src := readFixture(t, "contracts", "Verifier.sol")
	r := CompareBytecode(dep, dep, VKConstants(src))
	if r.Match != "equal" || len(r.VKMissing) != 0 || r.VKChecked != 20 {
		t.Fatalf("self compare: %+v", r)
	}
	code, meta := StripMetadata(dep.Bytes)
	if len(meta) == 0 || len(code)+len(meta) != len(dep.Bytes) {
		t.Fatalf("metadata not found: %d + %d", len(code), len(meta))
	}
	// a rebuild that differs only in metadata
	alt := append([]byte{}, dep.Bytes...)
	alt[len(code)+10] ^= 0xff
	r = CompareBytecode(dep, &Code{Bytes: alt, From: "local"}, nil)
	if r.Match != "metadata-only" {
		t.Fatalf("metadata-only: %+v", r)
	}
	alt = append([]byte{}, dep.Bytes...)
	alt[100] ^= 0xff
	r = CompareBytecode(dep, &Code{Bytes: alt, From: "local"}, nil)
	if r.Match != "different" || r.FirstDiff != 100 {
		t.Fatalf("different: %+v", r)
	}
	// the VK of another setup is not in this code
	other := []Constant{{Name: "ALPHA_X", Value: "0x1234"}}
	if r := CompareBytecode(dep, nil, other); len(r.VKFound) != 0 || !strings.Contains(r.VKExtractNote, "another VK") {
		t.Fatalf("foreign VK: %+v", r)
	}
	// artifact JSON with immutables masked
	art := `{"deployedBytecode":{"object":"0x6001600255","immutableReferences":{"7":[{"start":1,"length":1}]}}}`
	c, err := ParseCode("artifact", []byte(art))
	if err != nil || len(c.Masks) != 1 {
		t.Fatalf("artifact: %+v %v", c, err)
	}
	dep2, _ := ParseCode("dep", []byte("0x6009600255"))
	if r := CompareBytecode(dep2, c, nil); r.Match != "equal" {
		t.Fatalf("immutable masked: %+v", r)
	}
}

func TestCeremony(t *testing.T) {
	c, err := ScanCeremony(fixture.Dir(t, "sol-gnark-abi"))
	if err != nil {
		t.Fatal(err)
	}
	if c.Verdict != "single-party" || !strings.Contains(c.Detail, "cmd/export/main.go:21") {
		t.Fatalf("verdict: %s (%s)", c.Verdict, c.Detail)
	}
	kinds := map[string]string{}
	for _, a := range c.Artifacts {
		kinds[a.File] = a.Kind
	}
	if kinds["keys/verifier.vk"] != "verifying-key" || len(kinds) != 1 {
		t.Fatalf("artifacts: %v", kinds)
	}
	// snarkjs zkey and ptau contribution counts
	dir := t.TempDir()
	write := func(name, magic string, sections map[uint32][]byte) {
		var b []byte
		b = append(b, magic...)
		b = binary.LittleEndian.AppendUint32(b, 1)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(sections)))
		for _, typ := range []uint32{1, 7, 10} {
			s, ok := sections[typ]
			if !ok {
				continue
			}
			b = binary.LittleEndian.AppendUint32(b, typ)
			b = binary.LittleEndian.AppendUint64(b, uint64(len(s)))
			b = append(b, s...)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	zk := append(make([]byte, 64), 3, 0, 0, 0)
	write("circuit_final.zkey", "zkey", map[uint32][]byte{1: {1, 0, 0, 0}, 10: zk})
	write("pot12_final.ptau", "ptau", map[uint32][]byte{1: {1, 0, 0, 0}, 7: {5, 0, 0, 0}})
	write("circuit_0000.zkey", "zkey", map[uint32][]byte{1: {1, 0, 0, 0}})
	c, err = ScanCeremony(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, a := range c.Artifacts {
		got[a.File] = a.Contributions
	}
	if got["circuit_final.zkey"] != 3 || got["pot12_final.ptau"] != 5 || got["circuit_0000.zkey"] != 0 {
		t.Fatalf("contributions: %v", got)
	}
	if c.Verdict != "keys-without-provenance" {
		t.Errorf("verdict %s", c.Verdict)
	}
}
