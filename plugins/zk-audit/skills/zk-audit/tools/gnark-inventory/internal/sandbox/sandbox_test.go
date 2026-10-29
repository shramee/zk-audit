package sandbox

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestMain doubles as the sandboxed helper: stage 2 execs the test binary
// itself with ZK_SANDBOX_HELPER set, which performs one action and exits.
func TestMain(m *testing.M) {
	Stage2()
	if action := os.Getenv("ZK_SANDBOX_HELPER"); action != "" {
		os.Exit(helper(action, os.Args[1:]))
	}
	os.Exit(m.Run())
}

func helper(action string, args []string) int {
	switch action {
	case "dial":
		c, err := net.DialTimeout("tcp", args[0], 2*time.Second)
		if err != nil {
			fmt.Println("dial failed:", err)
			return 3
		}
		c.Close()
		fmt.Println("dial ok")
		return 0
	case "write":
		if err := os.WriteFile(args[0], []byte("x"), 0o644); err != nil {
			fmt.Println("write failed:", err)
			return 3
		}
		fmt.Println("write ok")
		return 0
	case "read":
		b, err := os.ReadFile(args[0])
		if err != nil {
			fmt.Println("read failed:", err)
			return 3
		}
		fmt.Printf("read ok: %s\n", b)
		return 0
	case "alloc":
		var n int
		fmt.Sscan(args[0], &n)
		buf := make([]byte, n<<20)
		for i := 0; i < len(buf); i += 4096 {
			buf[i] = 1
		}
		fmt.Println("alloc ok")
		return 0
	case "sleep":
		time.Sleep(time.Minute)
		return 0
	case "env":
		for _, k := range args {
			fmt.Printf("%s=%s\n", k, os.Getenv(k))
		}
		return 0
	}
	return 99
}

// engine returns the usable OS engine or skips. ZK_AUDIT_REQUIRE_SANDBOX=1
// turns the skip into a failure (CI on a runner where bwrap must work).
func engine(t *testing.T) *Engine {
	t.Helper()
	e, err := Detect("auto")
	if err != nil {
		t.Fatal(err)
	}
	if e.Name == None {
		if os.Getenv("ZK_AUDIT_REQUIRE_SANDBOX") == "1" {
			t.Fatalf("no OS sandbox: %s", e.Reason)
		}
		t.Skipf("no OS sandbox: %s", e.Reason)
	}
	return e
}

type result struct {
	code int
	out  string
}

func runHelper(t *testing.T, opt Options, action string, args ...string) result {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	opt.Stdout, opt.Stderr = &out, &errb
	opt.Env = append(opt.Env, "ZK_SANDBOX_HELPER="+action)
	if opt.GoCache == "" {
		opt.GoCache = filepath.Join(t.TempDir(), "gocache")
	}
	code, _, err := Run(append([]string{self}, args...), opt)
	if err != nil {
		t.Fatalf("%s: %v (%s)", action, err, errb.String())
	}
	return result{code, out.String() + errb.String()}
}

func TestGoEnv(t *testing.T) {
	env := GoEnv([]string{
		"PATH=/bin", "HOME=/h", "GITHUB_TOKEN=secret", "AWS_SECRET_ACCESS_KEY=x", "SSH_AUTH_SOCK=/s",
		"GOFLAGS=-toolexec=/evil", "CGO_ENABLED=1", "GOPROXY=https://proxy", "GOTOOLCHAIN=auto",
		"LC_ALL=C", "HTTPS_PROXY=http://p", "KEEP_ME=1",
	}, "-mod=mod", "/cache", false, []string{"KEEP_ME", "NEW=2"})
	m := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		m[k] = v
	}
	want := map[string]string{"PATH": "/bin", "HOME": "/h", "LC_ALL": "C", "CGO_ENABLED": "0", "GOTOOLCHAIN": "local",
		"GOWORK": "off", "GOFLAGS": "-mod=mod", "GOPROXY": "off", "GOCACHE": "/cache", "KEEP_ME": "1", "NEW": "2", MarkerEnv: "1"}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("%s=%q, want %q", k, m[k], v)
		}
	}
	for _, k := range []string{"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "SSH_AUTH_SOCK", "HTTPS_PROXY"} {
		if _, ok := m[k]; ok {
			t.Errorf("%s must be dropped", k)
		}
	}
	net := GoEnv([]string{"GOPROXY=https://proxy", "HTTPS_PROXY=http://p"}, "", "", true, nil)
	if !strings.Contains(strings.Join(net, " "), "GOPROXY=https://proxy") || !strings.Contains(strings.Join(net, " "), "HTTPS_PROXY=http://p") {
		t.Errorf("network env not kept: %v", net)
	}
}

func TestDetectUnknown(t *testing.T) {
	if _, err := Detect("docker"); err == nil {
		t.Fatal("unknown engine accepted")
	}
	e, err := Detect("none")
	if err != nil || e.Name != None {
		t.Fatalf("%v %v", e, err)
	}
}

// TestNetworkDenied: a TCP listener on the host loopback is reachable
// without the sandbox and unreachable inside it (own network namespace).
func TestNetworkDenied(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	rw := t.TempDir()
	if r := runHelper(t, Options{RW: []string{rw}, Engine: None}, "dial", ln.Addr().String()); r.code != 0 {
		t.Fatalf("control: dial without sandbox failed: %s", r.out)
	}
	engine(t)
	if r := runHelper(t, Options{RW: []string{rw}}, "dial", ln.Addr().String()); r.code == 0 {
		t.Fatalf("dial succeeded inside the sandbox: %s", r.out)
	}
	if r := runHelper(t, Options{RW: []string{rw}, Network: true}, "dial", ln.Addr().String()); r.code != 0 {
		t.Fatalf("--allow-network: dial failed: %s", r.out)
	}
}

// TestWritesConfined: writes land only in --rw directories; --ro
// directories and everything else are read-only; the home directory is
// masked so files in it cannot be read.
func TestWritesConfined(t *testing.T) {
	engine(t)
	rw, ro, other := t.TempDir(), t.TempDir(), t.TempDir()
	home := t.TempDir()
	os.WriteFile(filepath.Join(home, "secret"), []byte("token"), 0o600)
	os.WriteFile(filepath.Join(ro, "src.go"), []byte("package x"), 0o644)
	opt := Options{RW: []string{rw}, RO: []string{ro}, Home: home}
	if r := runHelper(t, opt, "write", filepath.Join(rw, "ok")); r.code != 0 {
		t.Fatalf("write to --rw failed: %s", r.out)
	}
	if _, err := os.Stat(filepath.Join(rw, "ok")); err != nil {
		t.Fatal("write to --rw did not reach the host")
	}
	for _, p := range []string{filepath.Join(ro, "new"), filepath.Join(ro, "src.go"), filepath.Join(other, "x")} {
		if r := runHelper(t, opt, "write", p); r.code == 0 {
			t.Errorf("write to %s succeeded inside the sandbox", p)
		}
	}
	if r := runHelper(t, opt, "read", filepath.Join(ro, "src.go")); r.code != 0 {
		t.Errorf("read of --ro failed: %s", r.out)
	}
	if r := runHelper(t, opt, "read", filepath.Join(home, "secret")); r.code == 0 {
		t.Errorf("home directory not masked: %s", r.out)
	}
	runHelper(t, opt, "write", filepath.Join(home, "planted"))
	if _, err := os.Stat(filepath.Join(home, "planted")); err == nil {
		t.Error("a write to the masked home reached the host")
	}
}

func TestMemoryLimit(t *testing.T) {
	rw := t.TempDir()
	for _, eng := range []string{"", None} {
		if eng == "" {
			engine(t)
		}
		if r := runHelper(t, Options{RW: []string{rw}, MemMB: 256, Engine: eng}, "alloc", "1024"); r.code == 0 {
			t.Errorf("engine %q: 1 GiB allocation under a 256 MiB limit succeeded: %s", eng, r.out)
		}
		if r := runHelper(t, Options{RW: []string{rw}, MemMB: 2048, Engine: eng}, "alloc", "64"); r.code != 0 {
			t.Errorf("engine %q: 64 MiB under a 2 GiB limit failed: %s", eng, r.out)
		}
	}
}

func TestTimeout(t *testing.T) {
	rw := t.TempDir()
	start := time.Now()
	r := runHelper(t, Options{RW: []string{rw}, Timeout: time.Second, Engine: None}, "sleep")
	if r.code != ExitTimeout || time.Since(start) > 20*time.Second || !strings.Contains(r.out, "time limit") {
		t.Fatalf("code %d after %s: %s", r.code, time.Since(start), r.out)
	}
	engine(t)
	start = time.Now()
	r = runHelper(t, Options{RW: []string{rw}, Timeout: time.Second}, "sleep")
	if r.code != ExitTimeout || time.Since(start) > 20*time.Second {
		t.Fatalf("bwrap: code %d after %s: %s", r.code, time.Since(start), r.out)
	}
}

func TestEnvInside(t *testing.T) {
	rw := t.TempDir()
	t.Setenv("ZK_TEST_SECRET", "s3cret")
	r := runHelper(t, Options{RW: []string{rw}, Engine: None}, "env", "CGO_ENABLED", "GOTOOLCHAIN", "GOPROXY", "GOFLAGS", "ZK_TEST_SECRET", MarkerEnv)
	for _, want := range []string{"CGO_ENABLED=0", "GOTOOLCHAIN=local", "GOPROXY=off", "GOFLAGS=-mod=mod", "ZK_TEST_SECRET=\n", MarkerEnv + "=1"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("want %q in %s", want, r.out)
		}
	}
}

// TestGoCommandInside runs the go command inside the sandbox: cgo is off,
// the toolchain is local, and a test that needs cgo cannot build.
func TestGoCommandInside(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go")
	}
	engine(t)
	mod := t.TempDir()
	os.WriteFile(filepath.Join(mod, "go.mod"), []byte("module example.com/sbx\n\ngo 1.21\n"), 0o644)
	// The test calls F, which only the cgo file defines: with cgo disabled
	// the go command excludes that file and the test does not build.
	os.WriteFile(filepath.Join(mod, "a_test.go"), []byte("package sbx\n\nimport \"testing\"\n\nfunc TestA(t *testing.T) { F() }\n"), 0o644)
	os.WriteFile(filepath.Join(mod, "c.go"), []byte("package sbx\n\n// #include <stdlib.h>\nimport \"C\"\n\nfunc F() { C.free(nil) }\n"), 0o644)
	var out bytes.Buffer
	opt := Options{RW: []string{mod}, Stdout: &out, Stderr: &out, GoCache: filepath.Join(t.TempDir(), "c"), Timeout: 5 * time.Minute}
	code, _, err := Run([]string{"go", "env", "CGO_ENABLED", "GOTOOLCHAIN"}, opt)
	if err != nil || code != 0 || !strings.Contains(out.String(), "0\nlocal") {
		t.Fatalf("go env: %d %v %s", code, err, out.String())
	}
	out.Reset()
	code, _, err = Run([]string{"go", "-C", mod, "test", "./..."}, opt)
	if err != nil || code == 0 || !strings.Contains(out.String(), "undefined: F") {
		t.Fatalf("a cgo package built with cgo disabled: %d %v %s", code, err, out.String())
	}
	os.WriteFile(filepath.Join(mod, "c.go"), []byte("package sbx\n\nfunc F() {}\n"), 0o644)
	out.Reset()
	code, _, err = Run([]string{"go", "-C", mod, "test", "-count=1", "./..."}, opt)
	if err != nil || code != 0 {
		t.Fatalf("go test inside the sandbox: %d %v %s", code, err, out.String())
	}
}

func TestCommandNotFound(t *testing.T) {
	code, _, err := Run([]string{"no-such-command-zk"}, Options{RW: []string{t.TempDir()}, Engine: None, Stderr: &bytes.Buffer{}})
	if err != nil || code != ExitNotFound {
		t.Fatalf("%d %v", code, err)
	}
}

func TestDarwinProfile(t *testing.T) {
	p := darwinProfile([]string{"/Users/a/out"}, false)
	for _, want := range []string{"(deny network*)", "(deny file-write*)", `(subpath "/Users/a/out")`, `(subpath "/private/tmp")`} {
		if !strings.Contains(p, want) {
			t.Errorf("profile lacks %s:\n%s", want, p)
		}
	}
	if strings.Contains(darwinProfile(nil, true), "deny network") {
		t.Error("network allowed but denied in the profile")
	}
}

// TestForgeInside runs a Foundry test inside the sandbox with --root (the
// allowlist-friendly form), using solc builds already on the machine.
func TestForgeInside(t *testing.T) {
	if _, err := exec.LookPath("forge"); err != nil {
		t.Skip("no forge")
	}
	engine(t)
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "test"), 0o755)
	os.WriteFile(filepath.Join(dir, "foundry.toml"), []byte("[profile.default]\nsrc = \"src\"\ntest = \"test\"\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "test", "PoC.t.sol"), []byte("// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract PoC_X { function test_one() public pure { require(1 + 1 == 2, \"m\"); } }\n"), 0o644)
	if out, err := exec.Command("forge", "build", "--root", dir, "--offline").CombinedOutput(); err != nil {
		t.Skipf("forge cannot build offline outside the sandbox either (no cached solc?): %s", out)
	}
	os.RemoveAll(filepath.Join(dir, "out"))
	os.RemoveAll(filepath.Join(dir, "cache"))
	var out bytes.Buffer
	code, _, err := Run([]string{"forge", "test", "--root", dir, "--offline"}, Options{RW: []string{dir}, Stdout: &out, Stderr: &out, GoCache: filepath.Join(t.TempDir(), "c")})
	if err != nil || code != 0 || !strings.Contains(out.String(), "1 passed") {
		t.Fatalf("forge test in the sandbox: %d %v %s", code, err, out.String())
	}
}
