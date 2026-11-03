//go:build !windows

package trace

import (
	"os/exec"
	"syscall"
)

// detach starts the process in its own session so it keeps running after the
// step that launched it exits.
func detach(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
