//go:build windows

package trace

import "os/exec"

// detach is a no-op on Windows: kernel tracing is Linux-only, so the DNS
// logger never runs there.
func detach(cmd *exec.Cmd) {}
