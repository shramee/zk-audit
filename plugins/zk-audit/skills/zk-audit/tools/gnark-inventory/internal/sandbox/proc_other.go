//go:build !unix

package sandbox

import (
	"os"
	"os/exec"
)

func setProcessGroup(cmd *exec.Cmd) {}

func signalOf(ee *exec.ExitError) int { return 0 }

// Stage2 runs the command without limits where the OS has no rlimits.
func Stage2() {
	if _, ok := os.LookupEnv(stage2Env); !ok {
		return
	}
	os.Unsetenv(stage2Env)
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		os.Exit(ExitNotFound)
	}
	os.Exit(0)
}
