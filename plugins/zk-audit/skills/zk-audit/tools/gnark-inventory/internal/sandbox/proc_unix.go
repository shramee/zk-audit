//go:build unix

package sandbox

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
)

// setProcessGroup puts the command in its own process group and kills the
// whole group when the time limit expires.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		return cmd.Process.Kill()
	}
}

func signalOf(ee *exec.ExitError) int {
	if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return int(ws.Signal())
	}
	return 0
}

// Stage2 runs inside the sandbox when the stage-2 variable is set: it sets
// the address-space limit and disables core dumps on itself, then replaces
// itself with the command (os.Args[1:]). It returns only when the variable
// is not set. Call it first thing in main.
func Stage2() {
	v, ok := os.LookupEnv(stage2Env)
	if !ok {
		return
	}
	os.Unsetenv(stage2Env)
	if len(os.Args) < 2 {
		os.Stderr.WriteString("sandbox: stage 2 without a command\n")
		os.Exit(ExitSetup)
	}
	if n, err := strconv.ParseUint(v, 10, 64); err == nil && n > 0 {
		lim := &syscall.Rlimit{Cur: n, Max: n}
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, lim); err != nil {
			os.Stderr.WriteString("sandbox: cannot set the memory limit: " + err.Error() + "\n")
			os.Exit(ExitSetup)
		}
	}
	_ = syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	err := syscall.Exec(os.Args[1], os.Args[1:], os.Environ())
	os.Stderr.WriteString("sandbox: exec " + os.Args[1] + ": " + err.Error() + "\n")
	os.Exit(ExitNotFound)
}
