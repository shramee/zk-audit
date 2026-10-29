package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/shramee/zk-audit/plugins/zk-audit/skills/zk-audit/tools/gnark-inventory/internal/sandbox"
)

// listFlag collects a repeatable flag.
type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

// cmdSandbox runs a command under the OS sandbox and returns its exit status
// (124 time limit, 125 sandbox setup failure, 127 command not found).
func cmdSandbox(args []string, stdout, stderr io.Writer) (int, error) {
	fs := flag.NewFlagSet("sandbox", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var rw, ro, env listFlag
	fs.Var(&rw, "rw", "writable directory (repeatable): the PoC worktree, the output directory")
	fs.Var(&ro, "ro", "further readable directory (repeatable): the target repository")
	fs.Var(&env, "env", "NAME or NAME=VALUE to pass into the sandbox (repeatable)")
	cwd := fs.String("cwd", "", "working directory (default: the first --rw directory)")
	timeout := fs.Int("timeout", int(sandbox.DefaultTimeout/time.Second), "wall-clock limit in seconds")
	mem := fs.Int("mem", sandbox.DefaultMemMB, "address-space limit per process in MiB (-1: none)")
	network := fs.Bool("allow-network", false, "keep the network (only with the user's consent)")
	gocache := fs.String("gocache", "", "writable GOCACHE (default ~/.zk-audit/gocache, separate from the user's cache)")
	goflags := fs.String("goflags", "-mod=mod", "GOFLAGS inside the sandbox")
	engine := fs.String("engine", "auto", "auto, bwrap, sandbox-exec or none")
	require := fs.Bool("require", false, "fail (125) instead of falling back to no OS sandbox")
	check := fs.Bool("check", false, "print the engine that would be used and exit")
	if err := fs.Parse(args); err != nil {
		return 2, err
	}
	if *check {
		e, err := sandbox.Detect(*engine)
		if err != nil {
			return sandbox.ExitSetup, err
		}
		if e.Name == sandbox.None {
			fmt.Fprintf(stdout, "sandbox: none (isolates %s only): %s\n", strings.Join(e.Isolates, ", "), e.Reason)
			if *require {
				return sandbox.ExitSetup, nil
			}
			return 0, nil
		}
		fmt.Fprintf(stdout, "sandbox: %s %s (isolates %s)\n", e.Name, e.Version, strings.Join(e.Isolates, ", "))
		return 0, nil
	}
	if fs.NArg() == 0 {
		return 2, fmt.Errorf("sandbox: want [flags] -- COMMAND [ARGS...]")
	}
	if len(rw) == 0 && *cwd == "" {
		return 2, fmt.Errorf("sandbox: name at least one --rw directory (the worktree or the output directory)")
	}
	code, _, err := sandbox.Run(fs.Args(), sandbox.Options{
		RW: rw, RO: ro, Env: env, Cwd: *cwd, Timeout: time.Duration(*timeout) * time.Second, MemMB: *mem,
		Network: *network, GoCache: *gocache, GoFlags: *goflags, Engine: *engine, Require: *require,
		Stdin: os.Stdin, Stdout: stdout, Stderr: stderr,
	})
	if err != nil {
		fmt.Fprintln(stderr, "gnark-inventory:", err)
	}
	return code, nil
}
