package diff

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func gitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	dir := t.TempDir()
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"config", "user.email", "t@example.com"}, {"config", "user.name", "t"}, {"config", "commit.gpgsign", "false"}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	return dir
}

func commit(t *testing.T, dir string, files map[string]string, msg string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(dir, p)
		if c == "" {
			os.Remove(full)
			continue
		}
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{"add", "-A"}, {"commit", "-q", "-m", msg}} {
		if out, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
}

const baseCircuit = `package ballot

import "github.com/consensys/gnark/frontend"

type BallotCircuit struct {
	Root   frontend.Variable ` + "`gnark:\",public\"`" + `
	Choice frontend.Variable ` + "`gnark:\",public\"`" + `
	Secret frontend.Variable ` + "`gnark:\",secret\"`" + `
}

func (c *BallotCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.Root, c.Secret)
	api.AssertIsBoolean(c.Choice)
	bits := api.ToBinary(c.Secret, 64)
	_ = bits
	r := newChecker(api)
	r.Check(c.Choice, 8)
	return nil
}

func helper(api frontend.API, x frontend.Variable) {
	api.AssertIsDifferent(x, 0)
}
`

const headCircuit = `package ballot

import "github.com/consensys/gnark/frontend"

type BallotCircuit struct {
	Choice frontend.Variable ` + "`gnark:\",public\"`" + `
	Root   frontend.Variable ` + "`gnark:\",public\"`" + `
	Secret frontend.Variable ` + "`gnark:\",secret\"`" + `
	Salt   frontend.Variable
}

const strict = false

func (c *BallotCircuit) Define(api frontend.API) error {
	if strict {
		api.AssertIsBoolean(c.Choice)
	}
	bits := api.ToBinary(c.Secret, 64)
	_ = bits
	out, _ := api.Compiler().NewHint(tallyHint, 1, c.Choice)
	_ = out
	return nil
}
`

const verifierSol = `pragma solidity ^0.8.0;
contract BallotVerifier {
    uint256 constant ALPHA_X = 1;
    uint256 constant DELTA_NEG_X = 2;
    function verifyProof(uint256[8] calldata proof, uint256[2] calldata input) public view {}
}
`

const ballotSol = `pragma solidity ^0.8.0;
contract Ballot {
    IVerifier verifier;
    function cast(uint256[8] calldata proof, uint256 root, uint256 choice) external {
        verifier.verifyProof(proof, [root, choice]);
    }
}
`

func TestCompare(t *testing.T) {
	dir := gitRepo(t)
	commit(t, dir, map[string]string{
		"go.mod":                       "module example.com/ballot\n\ngo 1.22\n\nrequire (\n\tgithub.com/consensys/gnark v0.13.0\n\tgithub.com/consensys/gnark-crypto v0.18.0\n)\n",
		"ballot/circuit.go":            baseCircuit,
		"ballot/circuit_test.go":       "package ballot\n\nfunc t(api frontend.API) { api.AssertIsEqual(1, 1) }\n",
		"contracts/BallotVerifier.sol": verifierSol,
		"contracts/Ballot.sol":         ballotSol,
		"keys/ballot.vk":               "vk-1",
		"README.md":                    "hello\n",
	}, "base")
	exec.Command("git", "-C", dir, "branch", "base").Run()
	commit(t, dir, map[string]string{
		"go.mod":                       "module example.com/ballot\n\ngo 1.22\n\nrequire (\n\tgithub.com/consensys/gnark v0.14.0\n\tgithub.com/consensys/gnark-crypto v0.18.0\n)\n",
		"ballot/circuit.go":            headCircuit,
		"ballot/circuit_test.go":       "package ballot\n",
		"contracts/BallotVerifier.sol": strings.Replace(verifierSol, "ALPHA_X = 1", "ALPHA_X = 7", 1),
		"contracts/Ballot.sol":         strings.Replace(ballotSol, "[root, choice]", "[choice, root]", 1),
		"keys/ballot.vk":               "vk-2",
		"README.md":                    "hello again\n",
	}, "head")

	res, err := Compare(dir, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Files) != 7 {
		t.Errorf("files: %+v", res.Files)
	}
	want := []struct{ kind, file, detail string }{
		{GnarkVersion, "go.mod", "github.com/consensys/gnark v0.13.0 → v0.14.0"},
		{ConstraintRemoved, "ballot/circuit.go", "AssertIsEqual: 1 → 0 calls"},
		{ConstraintRemoved, "ballot/circuit.go", "AssertIsDifferent: function removed"},
		{RangeCheckRemoved, "ballot/circuit.go", "Check: 1 → 0 calls"},
		{ConstraintConditional, "ballot/circuit.go", "AssertIsBoolean under a Go if: 0 → 1 of 1 calls"},
		{HintAdded, "ballot/circuit.go", "NewHint calls 0 → 1"},
		{PublicInputChanged, "ballot/circuit.go", "public inputs [Root, Choice] → [Choice, Root]: re-ordered"},
		{VerifierChanged, "contracts/BallotVerifier.sol", "verifier contract changed"},
		{VerifyCallChanged, "contracts/Ballot.sol", "added or changed: verifier.verifyProof(proof, [choice, root]);"},
		{VKChanged, "keys/ballot.vk", "verifying-key file changed"},
	}
	for _, w := range want {
		found := false
		for _, tr := range res.Triggers {
			if tr.Kind == w.kind && tr.File == w.file && strings.Contains(tr.Detail, w.detail) {
				found = true
			}
		}
		if !found {
			t.Errorf("missing trigger %s %s %q", w.kind, w.file, w.detail)
		}
	}
	for _, tr := range res.Triggers {
		if strings.HasSuffix(tr.File, "_test.go") || tr.File == "README.md" {
			t.Errorf("trigger on a test or doc file: %+v", tr)
		}
		if tr.Kind == ConstraintRemoved && strings.Contains(tr.Detail, "ToBinary") {
			t.Errorf("ToBinary was kept: %+v", tr)
		}
	}
	if res.Counts[ConstraintRemoved] != 2 || res.MergeBase == "" || res.HeadSHA == res.BaseSHA {
		t.Errorf("counts %v, merge base %q", res.Counts, res.MergeBase)
	}
	md := res.Markdown()
	for _, s := range []string{"## High-risk triggers", "| public-input-changed | `ballot/circuit.go:5` | BallotCircuit |", "- M `README.md`"} {
		if !strings.Contains(md, s) {
			t.Errorf("markdown lacks %q:\n%s", s, md)
		}
	}
	// deterministic
	again, _ := Compare(dir, "base", "HEAD")
	if again.Markdown() != md {
		t.Error("two runs differ")
	}
}

func TestCompareSecretOnlyAndNoTriggers(t *testing.T) {
	dir := gitRepo(t)
	commit(t, dir, map[string]string{"c.go": baseCircuit}, "base")
	exec.Command("git", "-C", dir, "branch", "base").Run()
	commit(t, dir, map[string]string{"c.go": strings.Replace(baseCircuit, "Secret frontend.Variable", "Secret, Pepper frontend.Variable", 1)}, "secret only")
	res, err := Compare(dir, "base", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Triggers) != 0 {
		t.Errorf("a secret-field change is no public-input trigger: %+v", res.Triggers)
	}
}

func TestCompareRejectsBadRevisions(t *testing.T) {
	dir := gitRepo(t)
	commit(t, dir, map[string]string{"a.txt": "x"}, "one")
	for _, r := range []string{"no-such-branch", "--output=/tmp/x", "-p"} {
		if _, err := Compare(dir, r, "HEAD"); err == nil {
			t.Errorf("revision %q accepted", r)
		}
	}
}

func TestGitIgnoresRepoConfig(t *testing.T) {
	dir := gitRepo(t)
	marker := filepath.Join(t.TempDir(), "pwned")
	commit(t, dir, map[string]string{"a.go": "package a\n"}, "one")
	exec.Command("git", "-C", dir, "branch", "base").Run()
	commit(t, dir, map[string]string{"a.go": "package a\n\nvar x = 1\n"}, "two")
	// a hostile repository config: fsmonitor and an external diff driver
	for _, kv := range [][2]string{{"core.fsmonitor", "touch " + marker}, {"diff.external", "touch " + marker}} {
		exec.Command("git", "-C", dir, "config", kv[0], kv[1]).Run()
	}
	os.WriteFile(filepath.Join(dir, "a.go"), []byte("package a // dirty\n"), 0o644)
	if _, err := Compare(dir, "base", "HEAD"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("repository config ran a command")
	}
}
