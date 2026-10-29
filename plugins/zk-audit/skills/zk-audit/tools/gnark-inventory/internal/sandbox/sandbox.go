// Package sandbox runs a command on untrusted code (a PoC `go test`, a
// `forge test`, the inventory's `go list`) with OS isolation: on Linux under
// bubblewrap (no network namespace, read-only root, home and /tmp masked,
// writes only to named directories), on macOS under sandbox-exec (network
// denied, writes only to named directories), and otherwise with a printed
// warning and only the limits that need no OS support. Every engine applies
// the same Go environment hardening (CGO_ENABLED=0, GOTOOLCHAIN=local,
// GOWORK=off, GOPROXY=off unless network is allowed, a scrubbed
// environment), an address-space limit and a wall-clock limit.
package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/fsutil"
)

// Exit statuses of Run besides the command's own.
const (
	ExitTimeout  = 124 // the time limit expired (as timeout(1))
	ExitSetup    = 125 // the sandbox could not be set up
	ExitNotFound = 127 // the command does not exist
)

// Engines.
const (
	Bwrap       = "bwrap"
	SandboxExec = "sandbox-exec"
	None        = "none"
)

// MarkerEnv is set inside every sandbox so nested invocations do not wrap
// themselves again.
const MarkerEnv = "ZK_AUDIT_SANDBOXED"

// stage2Env carries the memory limit to the second stage, which runs inside
// the sandbox, sets the limit on itself and execs the command.
const stage2Env = "ZK_AUDIT_SANDBOX_STAGE2"

// Options configure one run.
type Options struct {
	RW      []string      // writable directories (must exist)
	RO      []string      // further readable directories (the target repository)
	Cwd     string        // working directory (default: the first RW directory)
	Timeout time.Duration // wall-clock limit (default 10 minutes)
	MemMB   int           // address-space limit per process in MiB (default 8192; 0 keeps the default, <0 disables)
	Network bool          // keep the network (only with the user's consent)
	GoCache string        // writable GOCACHE (default ~/.zk-audit/gocache)
	GoFlags string        // GOFLAGS inside the sandbox (default "-mod=mod")
	Env     []string      // extra NAME or NAME=VALUE entries to pass in
	Engine  string        // auto (""), bwrap, sandbox-exec or none
	Require bool          // fail instead of falling back to none
	Home    string        // home directory to mask (default $HOME)
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// DefaultTimeout and DefaultMemMB are the limits when Options leave them zero.
const (
	DefaultTimeout = 10 * time.Minute
	DefaultMemMB   = 8192
)

// Engine is the result of probing for an isolation engine.
type Engine struct {
	Name    string `json:"engine"`
	Path    string `json:"path,omitempty"`
	Version string `json:"version,omitempty"`
	// Isolates lists what the engine isolates.
	Isolates []string `json:"isolates"`
	// Reason says why a better engine was not used.
	Reason string `json:"reason,omitempty"`
}

var (
	probeMu    sync.Mutex
	probeCache = map[string]*Engine{}
)

// Detect picks an engine. want is "", "auto", "bwrap", "sandbox-exec" or
// "none". An explicitly requested engine that is unusable is an error.
func Detect(want string) (*Engine, error) {
	probeMu.Lock()
	defer probeMu.Unlock()
	if e, ok := probeCache[want]; ok {
		return e, nil
	}
	e, err := detect(want)
	if err == nil {
		probeCache[want] = e
	}
	return e, err
}

func detect(want string) (*Engine, error) {
	none := &Engine{Name: None, Isolates: []string{"time", "memory (address space)", "go environment"}}
	switch want {
	case None:
		none.Reason = "engine none requested"
		return none, nil
	case "", "auto", Bwrap, SandboxExec:
	default:
		return nil, fmt.Errorf("unknown sandbox engine %q (want auto, bwrap, sandbox-exec or none)", want)
	}
	var reasons []string
	if (want == "" || want == "auto" || want == Bwrap) && runtime.GOOS == "linux" {
		if p, err := exec.LookPath("bwrap"); err == nil {
			if err := probeBwrap(p); err == nil {
				v, _ := exec.Command(p, "--version").Output()
				return &Engine{Name: Bwrap, Path: p, Version: strings.TrimSpace(string(v)),
					Isolates: []string{"network", "file writes", "home directory", "processes", "time", "memory (address space)", "go environment"}}, nil
			} else {
				reasons = append(reasons, "bwrap is installed but cannot create namespaces here: "+err.Error())
			}
		} else {
			reasons = append(reasons, "bwrap is not installed (apt install bubblewrap)")
		}
	}
	if (want == "" || want == "auto" || want == SandboxExec) && runtime.GOOS == "darwin" {
		if p, err := exec.LookPath("sandbox-exec"); err == nil {
			if out, err := exec.Command(p, "-p", "(version 1)(allow default)", "/usr/bin/true").CombinedOutput(); err == nil {
				return &Engine{Name: SandboxExec, Path: p, Isolates: []string{"network", "file writes", "time", "go environment"}}, nil
			} else {
				reasons = append(reasons, "sandbox-exec failed: "+strings.TrimSpace(string(out)))
			}
		} else {
			reasons = append(reasons, "sandbox-exec not found")
		}
	}
	if want == Bwrap || want == SandboxExec {
		if len(reasons) == 0 {
			reasons = append(reasons, want+" is not available on "+runtime.GOOS)
		}
		return nil, errors.New(strings.Join(reasons, "; "))
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "no OS sandbox for "+runtime.GOOS)
	}
	none.Reason = strings.Join(reasons, "; ")
	return none, nil
}

func probeBwrap(p string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	args := append(baseBwrapArgs(false), "--", "true")
	out, err := exec.CommandContext(ctx, p, args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return errors.New(msg)
	}
	return nil
}

func baseBwrapArgs(network bool) []string {
	a := []string{"--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp",
		"--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try",
		"--die-with-parent", "--new-session"}
	if !network {
		a = append(a, "--unshare-net")
	}
	if os.Geteuid() == 0 {
		a = append(a, "--cap-drop", "ALL")
	}
	return a
}

// passEnv lists the variables kept from the caller's environment; everything
// else (tokens, cloud credentials, SSH agent sockets) is dropped.
var passEnv = map[string]bool{
	"PATH": true, "HOME": true, "USER": true, "LOGNAME": true, "LANG": true, "TERM": true, "TZ": true,
	"GOROOT": true, "GOPATH": true, "GOMODCACHE": true, "GOOS": true, "GOARCH": true, "GOAMD64": true,
	"GOARM": true, "GOARM64": true, "GODEBUG": true, "GOMAXPROCS": true, "GOGC": true, "GOMEMLIMIT": true,
	"GOPRIVATE": true, "GONOPROXY": true, "GONOSUMDB": true, "GOSUMDB": true, "GOINSECURE": true,
	"FOUNDRY_PROFILE": true, "FOUNDRY_OFFLINE": true, "SOURCE_DATE_EPOCH": true,
}

// networkEnv passes through only when the network is allowed.
var networkEnv = map[string]bool{
	"GOPROXY": true, "HTTPS_PROXY": true, "HTTP_PROXY": true, "NO_PROXY": true,
	"https_proxy": true, "http_proxy": true, "no_proxy": true, "SSL_CERT_FILE": true, "SSL_CERT_DIR": true,
}

// GoEnv returns the hardened environment for running the go command on
// untrusted code: a scrubbed copy of environ with CGO_ENABLED=0,
// GOTOOLCHAIN=local, GOWORK=off, GOFLAGS=goflags, GOPROXY=off unless
// network is allowed, and GOCACHE when gocache is set. Extra entries (NAME
// or NAME=VALUE) pass through or are set.
func GoEnv(environ []string, goflags, gocache string, network bool, extra []string) []string {
	keep := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := keep[k]; !ok {
			order = append(order, k)
		}
		keep[k] = v
	}
	extraNames := map[string]bool{}
	for _, e := range extra {
		k, _, _ := strings.Cut(e, "=")
		extraNames[k] = true
	}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		switch {
		case passEnv[k], strings.HasPrefix(k, "LC_"), extraNames[k]:
			set(k, v)
		case network && networkEnv[k]:
			set(k, v)
		}
	}
	for _, e := range extra {
		if k, v, ok := strings.Cut(e, "="); ok {
			set(k, v)
		}
	}
	set("CGO_ENABLED", "0")
	set("GOTOOLCHAIN", "local")
	set("GOWORK", "off")
	set("GOFLAGS", goflags)
	set("GOENV", "off") // ignore a go.env written by anything but the user
	set("GOTELEMETRY", "off")
	if !network {
		set("GOPROXY", "off")
	}
	if gocache != "" {
		set("GOCACHE", gocache)
	}
	set(MarkerEnv, "1")
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+keep[k])
	}
	return out
}

// goEnvValue asks the go command for one setting, empty on failure.
func goEnvValue(name string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "env", name)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOFLAGS=")
	o, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(o))
}

// DefaultGoCache is the sandbox build cache: separate from the user's own
// GOCACHE, so code run in a sandbox cannot plant entries in the cache the
// user's other builds read.
func DefaultGoCache(home string) string {
	if home == "" {
		return ""
	}
	return filepath.Join(home, ".zk-audit", "gocache")
}

// Run runs argv under the selected engine and returns its exit status.
func Run(argv []string, opt Options) (int, *Engine, error) {
	if len(argv) == 0 {
		return ExitSetup, nil, errors.New("sandbox: no command")
	}
	eng, err := Detect(opt.Engine)
	if err != nil {
		return ExitSetup, nil, fmt.Errorf("sandbox: %w", err)
	}
	if eng.Name == None && opt.Require {
		return ExitSetup, eng, fmt.Errorf("sandbox: no usable OS sandbox and --require was given: %s", eng.Reason)
	}
	stderr := opt.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	if eng.Name == None {
		fmt.Fprintf(stderr, "sandbox: warning: no OS sandbox (%s); running with a time limit, a memory limit and a hardened go environment only. Network, file writes and the home directory are NOT isolated.\n", eng.Reason)
	}
	if opt.Timeout <= 0 {
		opt.Timeout = DefaultTimeout
	}
	if opt.MemMB == 0 {
		opt.MemMB = DefaultMemMB
	}
	if opt.GoFlags == "" {
		opt.GoFlags = "-mod=mod"
	}
	if opt.Home == "" {
		opt.Home, _ = os.UserHomeDir()
	}
	if opt.GoCache == "" {
		opt.GoCache = DefaultGoCache(opt.Home)
	}
	var rw, ro []string
	for _, d := range opt.RW {
		r, err := realDir(d)
		if err != nil {
			return ExitSetup, eng, fmt.Errorf("sandbox: --rw %s: %w", d, err)
		}
		rw = append(rw, r)
	}
	if opt.GoCache != "" {
		if err := os.MkdirAll(opt.GoCache, 0o755); err != nil {
			return ExitSetup, eng, fmt.Errorf("sandbox: gocache: %w", err)
		}
		r, err := realDir(opt.GoCache)
		if err != nil {
			return ExitSetup, eng, err
		}
		opt.GoCache = r
		rw = append(rw, r)
	}
	for _, d := range opt.RO {
		r, err := realDir(d)
		if err != nil {
			return ExitSetup, eng, fmt.Errorf("sandbox: --ro %s: %w", d, err)
		}
		ro = append(ro, r)
	}
	cwd := opt.Cwd
	if cwd == "" {
		if len(rw) > 0 && len(opt.RW) > 0 {
			cwd = rw[0]
		} else if cwd, err = os.Getwd(); err != nil {
			return ExitSetup, eng, err
		}
	}
	if cwd, err = realDir(cwd); err != nil {
		return ExitSetup, eng, fmt.Errorf("sandbox: --cwd: %w", err)
	}
	if !insideAny(cwd, rw) && !insideAny(cwd, ro) {
		ro = append(ro, cwd)
	}
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		fmt.Fprintf(stderr, "sandbox: %s: command not found\n", argv[0])
		return ExitNotFound, eng, nil
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return ExitSetup, eng, err
	}
	self, err := os.Executable()
	if err != nil {
		return ExitSetup, eng, err
	}
	if s, err := filepath.EvalSymlinks(self); err == nil {
		self = s
	}
	env := GoEnv(os.Environ(), opt.GoFlags, opt.GoCache, opt.Network, opt.Env)
	if opt.MemMB > 0 {
		env = append(env, fmt.Sprintf("%s=%d", stage2Env, int64(opt.MemMB)<<20))
	} else {
		env = append(env, stage2Env+"=0")
	}
	if eng.Name == Bwrap {
		env = setEnv(env, "TMPDIR", "/tmp")
	}
	inner := append([]string{self, bin}, argv[1:]...)

	var cmd *exec.Cmd
	ctx, cancel := context.WithTimeout(context.Background(), opt.Timeout)
	defer cancel()
	switch eng.Name {
	case Bwrap:
		args := baseBwrapArgs(opt.Network)
		if h := opt.Home; h != "" && h != "/" {
			if rh, err := filepath.EvalSymlinks(h); err == nil {
				args = append(args, "--tmpfs", rh)
			}
		}
		// Read-only re-binds of what the masked home or /tmp may hide.
		roBinds := append([]string{}, ro...)
		roBinds = append(roBinds, filepath.Dir(bin), self)
		if v := goEnvValue("GOROOT"); v != "" {
			roBinds = append(roBinds, v)
		}
		// The module cache is read-only, except when the user allowed the
		// network: then the go command may download into it.
		if v := goEnvValue("GOMODCACHE"); v != "" {
			if opt.Network {
				if err := os.MkdirAll(v, 0o755); err == nil {
					if r, err := filepath.EvalSymlinks(v); err == nil {
						rw = append(rw, r)
					}
				}
			} else {
				roBinds = append(roBinds, v)
			}
		}
		// Foundry and its solc builds (svm), read-only.
		for _, d := range []string{".foundry", ".svm", filepath.Join(".local", "share", "svm")} {
			roBinds = append(roBinds, filepath.Join(opt.Home, d))
		}
		if x := os.Getenv("XDG_DATA_HOME"); x != "" {
			roBinds = append(roBinds, filepath.Join(x, "svm"))
		}
		for _, d := range uniq(roBinds) {
			if r, err := filepath.EvalSymlinks(d); err == nil {
				args = append(args, "--ro-bind", r, r)
			}
		}
		for _, d := range uniq(rw) {
			args = append(args, "--bind", d, d)
		}
		args = append(args, "--chdir", cwd, "--clearenv")
		for _, kv := range env {
			k, v, _ := strings.Cut(kv, "=")
			args = append(args, "--setenv", k, v)
		}
		args = append(args, "--")
		args = append(args, inner...)
		cmd = exec.CommandContext(ctx, eng.Path, args...)
		cmd.Env = []string{}
	case SandboxExec:
		prof := darwinProfile(rw, opt.Network)
		cmd = exec.CommandContext(ctx, eng.Path, append([]string{"-p", prof}, inner...)...)
		cmd.Env = env
		cmd.Dir = cwd
	default:
		cmd = exec.CommandContext(ctx, inner[0], inner[1:]...)
		cmd.Env = env
		cmd.Dir = cwd
	}
	cmd.Stdin = opt.Stdin
	cmd.Stdout = opt.Stdout
	cmd.Stderr = stderr
	if cmd.Stdout == nil {
		cmd.Stdout = os.Stdout
	}
	setProcessGroup(cmd)
	start := time.Now()
	err = cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		fmt.Fprintf(stderr, "sandbox: time limit of %s reached after %s; killed\n", opt.Timeout, time.Since(start).Round(time.Second))
		return ExitTimeout, eng, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if code := ee.ExitCode(); code >= 0 {
			return code, eng, nil
		}
		return 128 + signalOf(ee), eng, nil
	}
	if err != nil {
		return ExitSetup, eng, fmt.Errorf("sandbox: %w", err)
	}
	return 0, eng, nil
}

func setEnv(env []string, k, v string) []string {
	for i, kv := range env {
		if strings.HasPrefix(kv, k+"=") {
			env[i] = k + "=" + v
			return env
		}
	}
	return append(env, k+"="+v)
}

func realDir(d string) (string, error) {
	a, err := filepath.Abs(d)
	if err != nil {
		return "", err
	}
	r, err := filepath.EvalSymlinks(a)
	if err != nil {
		return "", err
	}
	st, err := os.Stat(r)
	if err != nil {
		return "", err
	}
	if !st.IsDir() {
		return "", fmt.Errorf("%s is not a directory", r)
	}
	return r, nil
}

func insideAny(p string, dirs []string) bool {
	for _, d := range dirs {
		if fsutil.Inside(p, d) {
			return true
		}
	}
	return false
}

func uniq(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// darwinProfile is the sandbox-exec profile: everything allowed except
// network access and writes outside rw, the temporary directories and the
// terminal devices.
func darwinProfile(rw []string, network bool) string {
	var b bytes.Buffer
	b.WriteString("(version 1)\n(allow default)\n")
	if !network {
		b.WriteString("(deny network*)\n")
	}
	b.WriteString("(deny file-write*)\n(allow file-write*\n")
	paths := append([]string{"/private/tmp", "/private/var/folders"}, rw...)
	for _, p := range uniq(paths) {
		fmt.Fprintf(&b, "  (subpath %s)\n", strconv.Quote(p))
	}
	b.WriteString("  (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/tty\") (regex #\"^/dev/fd/\") (regex #\"^/dev/ttys\"))\n")
	return b.String()
}
