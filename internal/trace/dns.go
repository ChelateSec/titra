package trace

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const resolvPath = "/etc/resolv.conf"

// startDNS launches the DNS logger (titra dns) in the background and points
// the system resolver at it, so connections can be shown by domain name.
func startDNS(st *State, opt Options) error {
	r, err := StartResolver(opt.StateDir, opt.Titra, nil)
	if err != nil {
		return err
	}
	st.DNS, st.DNSLog, st.Resolv = true, r.LogPath, r.Backup
	return nil
}

// Resolver describes a running titra DNS logger.
type Resolver struct {
	LogPath string        `json:"log_path"`
	PID     int           `json:"pid"`
	Backup  *ResolvBackup `json:"backup,omitempty"`
}

// StartResolver launches `titra dns` (plus extra flags, e.g. an allowlist) as a
// detached process on 127.0.0.1:53 and points /etc/resolv.conf at it. Needs root.
func StartResolver(stateDir, titra string, extra []string) (*Resolver, error) {
	opt := Options{StateDir: stateDir, Titra: titra}
	cur, err := os.ReadFile(resolvPath)
	if err != nil {
		return nil, err
	}
	upstream := ""
	var keep []string
	for _, l := range strings.Split(string(cur), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			if upstream == "" && f[1] != "127.0.0.1" {
				upstream = f[1]
			}
			continue
		}
		if len(f) >= 1 && (f[0] == "search" || f[0] == "options" || f[0] == "domain") {
			keep = append(keep, l)
		}
	}
	if upstream == "" {
		return nil, fmt.Errorf("no upstream nameserver in %s", resolvPath)
	}

	logPath := filepath.Join(opt.StateDir, "dns.jsonl")
	ready := filepath.Join(opt.StateDir, "dns.ready")
	_ = os.Remove(ready)
	out, _ := os.OpenFile(filepath.Join(opt.StateDir, "dns.out"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	args := append([]string{"dns",
		"--listen", "127.0.0.1:53",
		"--upstream", upstream,
		"--log", logPath,
		"--ready", ready}, extra...)
	cmd := exec.Command(opt.Titra, args...)
	cmd.Stdout, cmd.Stderr = out, out
	detach(cmd) // own session, so it outlives this step
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_ = os.WriteFile(filepath.Join(opt.StateDir, "dns.pid"), []byte(fmt.Sprint(cmd.Process.Pid)), 0o644)
	go func() { _ = cmd.Wait() }()

	ok := false
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(ready); err == nil {
			ok = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ok {
		_ = cmd.Process.Kill()
		b, _ := os.ReadFile(filepath.Join(opt.StateDir, "dns.out"))
		return nil, fmt.Errorf("dns logger did not start: %s", strings.TrimSpace(string(b)))
	}

	bk := &ResolvBackup{Path: resolvPath, Content: string(cur)}
	if t, err := os.Readlink(resolvPath); err == nil {
		bk.LinkTarget = t
	}
	content := "# set by titra: DNS goes through the titra logger, then to " + upstream + "\nnameserver 127.0.0.1\n"
	for _, l := range keep {
		content += l + "\n"
	}
	tmp := resolvPath + ".titra"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		_ = cmd.Process.Kill()
		return nil, err
	}
	if err := os.Rename(tmp, resolvPath); err != nil { // replaces a symlink atomically
		_ = cmd.Process.Kill()
		return nil, err
	}
	return &Resolver{LogPath: logPath, PID: cmd.Process.Pid, Backup: bk}, nil
}

// StopResolver kills the logger and restores /etc/resolv.conf.
func StopResolver(r *Resolver) {
	if r == nil {
		return
	}
	if r.Backup != nil {
		restoreResolv(r.Backup)
	}
	if r.PID > 0 {
		if p, err := os.FindProcess(r.PID); err == nil {
			_ = p.Kill()
		}
	}
}

func restoreResolv(bk *ResolvBackup) {
	if bk.LinkTarget != "" {
		_ = os.Remove(bk.Path)
		_ = os.Symlink(bk.LinkTarget, bk.Path)
		return
	}
	_ = os.WriteFile(bk.Path, []byte(bk.Content), 0o644)
}
