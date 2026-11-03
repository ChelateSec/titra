// Package trace gives Titra full-job visibility. The tool shims only see the
// commands that go through them; an agent that runs /usr/bin/git directly, or
// exfiltrates with Python, walks around them. trace asks the Linux kernel's
// audit subsystem to record every process start, every outbound connection and
// every read of a credential file, then filters that record down to the
// processes that belong to this job.
//
// Tracing observes; it does not block. Blocking stays with the shims and the
// agent hook. What tracing adds is that nothing the job does is invisible.
package trace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Audit rule keys. Every rule Titra adds is tagged so its events are easy to
// pick out of a shared audit log.
const (
	KeyExec = "titra_exec"
	KeyNet  = "titra_net"
	KeyFile = "titra_file"
)

// State is written at start and read back at report time.
type State struct {
	Started   time.Time      `json:"started"`
	RootPID   int            `json:"root_pid"` // events must descend from this pid
	RootComm  string         `json:"root_comm"`
	Titra     string         `json:"titra"` // path of the titra binary (its own events are ignored)
	Workspace string         `json:"workspace"`
	Home      string         `json:"home"`
	AuditLog  string         `json:"audit_log"`
	Watched   []string       `json:"watched"`
	Procs     map[int]int    `json:"procs"`    // pid -> ppid snapshot at start
	ProcExe   map[int]string `json:"proc_exe"` // pid -> exe snapshot at start
	DNS       bool           `json:"dns"`
	DNSLog    string         `json:"dns_log,omitempty"`
	Resolv    *ResolvBackup  `json:"resolv,omitempty"`
	Locked    bool           `json:"locked"` // audit rules made immutable
	Warnings  []string       `json:"warnings,omitempty"`
}

// ResolvBackup is how /etc/resolv.conf looked before Titra pointed it at the
// DNS logger, so `titra trace stop` can put it back on self-hosted runners.
type ResolvBackup struct {
	Path       string `json:"path"`
	LinkTarget string `json:"link_target,omitempty"`
	Content    string `json:"content,omitempty"`
}

// Options for Start.
type Options struct {
	StateDir  string
	Titra     string
	Workspace string
	Home      string
	DNS       bool
	Lock      bool // make audit rules immutable until reboot (ephemeral runners)
}

// StatePath is where the state file lives inside a state dir.
func StatePath(dir string) string { return filepath.Join(dir, "trace.json") }

// SensitiveFiles are the credential stores an agent has no business reading.
func SensitiveFiles(workspace, home string) []string {
	var out []string
	if workspace != "" {
		out = append(out,
			filepath.Join(workspace, ".git", "config"), // actions/checkout persists the token here
			filepath.Join(workspace, ".git-credentials"),
			filepath.Join(workspace, ".env"),
			filepath.Join(workspace, ".npmrc"),
		)
	}
	if home != "" {
		out = append(out,
			filepath.Join(home, ".git-credentials"),
			filepath.Join(home, ".gitconfig"),
			filepath.Join(home, ".npmrc"),
			filepath.Join(home, ".pypirc"),
			filepath.Join(home, ".docker", "config.json"),
			filepath.Join(home, ".config", "gh", "hosts.yml"),
			filepath.Join(home, ".aws", "credentials"),
			filepath.Join(home, ".ssh"),
			filepath.Join(home, ".claude", ".credentials.json"),
		)
	}
	return out
}

// Start turns tracing on. Must run as root.
func Start(opt Options) (*State, error) {
	if os.Geteuid() != 0 {
		return nil, fmt.Errorf("trace start needs root (run it with sudo)")
	}
	if _, err := exec.LookPath("auditctl"); err != nil {
		return nil, fmt.Errorf("auditctl not found: install the auditd package")
	}
	if err := os.MkdirAll(opt.StateDir, 0o755); err != nil {
		return nil, err
	}
	st := &State{
		Started:   time.Now().UTC(),
		Titra:     opt.Titra,
		Workspace: opt.Workspace,
		Home:      opt.Home,
		AuditLog:  "/var/log/audit/audit.log",
	}

	if err := ensureAuditd(st); err != nil {
		return nil, err
	}
	_ = auditctl("-b", "16384")
	_ = auditctl("-r", "0")
	_ = auditctl("-e", "1")

	rules := [][]string{
		{"-a", "always,exit", "-F", "arch=b64", "-S", "execve", "-k", KeyExec},
		{"-a", "always,exit", "-F", "arch=b32", "-S", "execve", "-k", KeyExec},
		{"-a", "always,exit", "-F", "arch=b64", "-S", "connect", "-k", KeyNet},
	}
	for _, r := range rules {
		if err := auditctl(r...); err != nil && !strings.Contains(err.Error(), "exists") {
			return nil, fmt.Errorf("adding audit rule %v: %w", r, err)
		}
	}
	for _, f := range SensitiveFiles(opt.Workspace, opt.Home) {
		if _, err := os.Stat(filepath.Dir(f)); err != nil {
			continue // the kernel can only watch paths whose parent exists
		}
		if err := auditctl("-w", f, "-p", "r", "-k", KeyFile); err == nil || strings.Contains(err.Error(), "exists") {
			st.Watched = append(st.Watched, f)
		}
	}

	st.Procs, st.ProcExe = snapshotProcs()
	st.RootPID, st.RootComm = findRoot(st.Procs)

	if opt.DNS {
		if err := startDNS(st, opt); err != nil {
			st.Warnings = append(st.Warnings, "dns logging off: "+err.Error())
		}
	}
	if opt.Lock {
		if err := auditctl("-e", "2"); err == nil {
			st.Locked = true
		}
	}
	return st, Save(opt.StateDir, st)
}

// Save writes the state file.
func Save(dir string, st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(StatePath(dir), b, 0o644)
}

// Load reads the state file.
func Load(dir string) (*State, error) {
	b, err := os.ReadFile(StatePath(dir))
	if err != nil {
		return nil, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// Stop removes Titra's rules and restores DNS. For self-hosted runners; on
// ephemeral GitHub-hosted runners the VM is discarded anyway.
func Stop(dir string) error {
	st, err := Load(dir)
	if err != nil {
		return err
	}
	if st.Resolv != nil {
		restoreResolv(st.Resolv)
	}
	if pid, err := os.ReadFile(filepath.Join(dir, "dns.pid")); err == nil {
		if n, _ := strconv.Atoi(strings.TrimSpace(string(pid))); n > 0 {
			if p, err := os.FindProcess(n); err == nil {
				_ = p.Kill()
			}
		}
	}
	if st.Locked {
		return fmt.Errorf("audit rules are locked until reboot")
	}
	for _, k := range []string{KeyExec, KeyNet, KeyFile} {
		_ = auditctl("-D", "-k", k)
	}
	return nil
}

// Collect reads the audit log and returns this job's events. Must run as root
// (the audit log is root-only).
func Collect(st *State) ([]Event, error) {
	files, _ := filepath.Glob(st.AuditLog + "*")
	if len(files) == 0 {
		return nil, fmt.Errorf("no audit log at %s", st.AuditLog)
	}
	// audit.log.N is older than audit.log.(N-1); audit.log is newest.
	sort.Slice(files, func(i, j int) bool { return logAge(files[i], st.AuditLog) > logAge(files[j], st.AuditLog) })
	var buf bytes.Buffer
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	all := ParseLog(&buf)
	return Filter(st, all), nil
}

func logAge(f, base string) int {
	if f == base {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimPrefix(f, base+"."))
	if err != nil {
		return 0
	}
	return n
}

// Filter keeps events after start that descend from the job's root process,
// dropping Titra's own internal activity.
func Filter(st *State, all []Event) []Event {
	parent := map[int]int{}
	for pid, pp := range st.Procs {
		parent[pid] = pp
	}
	since := st.Started.Add(-2 * time.Second)
	for _, e := range all {
		if e.Time.Before(since) {
			continue
		}
		if e.PID > 0 {
			parent[e.PID] = e.PPID
		}
	}
	inJob := func(pid int) bool {
		if st.RootPID == 0 {
			return true
		}
		for i := 0; i < 128 && pid > 1; i++ {
			pp, ok := parent[pid]
			if !ok {
				return false
			}
			if pp == st.RootPID {
				return true
			}
			pid = pp
		}
		return false
	}
	var out []Event
	for _, e := range all {
		if e.Time.Before(since) || !inJob(e.PID) {
			continue
		}
		if e.Kind != "exec" && st.Titra != "" && e.Exe == st.Titra {
			continue // titra's own reads/connects (dns logger, report)
		}
		if e.Kind == "exec" && isTitraInternal(st, e) {
			continue
		}
		out = append(out, e)
	}
	return out
}

// isTitraInternal is true for titra subcommands and the sudo calls that run
// them — the guard's own plumbing, not the job's behaviour.
func isTitraInternal(st *State, e Event) bool {
	if st.Titra == "" {
		return false
	}
	if e.Exe == st.Titra && len(e.Args) > 0 && strings.HasPrefix(filepath.Base(e.Args[0]), "titra") {
		return true
	}
	if filepath.Base(e.Exe) == "sudo" {
		for _, a := range e.Args {
			if a == st.Titra {
				return true
			}
		}
	}
	return false
}

func ensureAuditd(st *State) error {
	if auditdPID() > 0 {
		return nil
	}
	tuneAuditdConf()
	attempts := [][]string{
		{"systemctl", "start", "auditd"},
		{"service", "auditd", "start"},
		{"auditd"},
	}
	for _, a := range attempts {
		if _, err := exec.LookPath(a[0]); err != nil {
			continue
		}
		_ = exec.Command(a[0], a[1:]...).Run()
		for i := 0; i < 30; i++ {
			if auditdPID() > 0 {
				return nil
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	return fmt.Errorf("could not start auditd")
}

// tuneAuditdConf raises the log size so a busy job doesn't rotate away its
// own history before the report reads it.
func tuneAuditdConf() {
	const p = "/etc/audit/auditd.conf"
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	var lines []string
	for _, l := range strings.Split(string(b), "\n") {
		k := strings.TrimSpace(strings.SplitN(l, "=", 2)[0])
		switch k {
		case "max_log_file":
			l = "max_log_file = 256"
		case "num_logs":
			l = "num_logs = 8"
		}
		lines = append(lines, l)
	}
	_ = os.WriteFile(p, []byte(strings.Join(lines, "\n")), 0o640)
}

func auditdPID() int {
	out, err := exec.Command("auditctl", "-s").Output()
	if err != nil {
		return 0
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "pid" {
			n, _ := strconv.Atoi(f[1])
			return n
		}
	}
	return 0
}

func auditctl(args ...string) error {
	out, err := exec.Command("auditctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return nil
}

// snapshotProcs records the process tree as it is before tracing starts, so
// processes that already existed (the step shell, the runner) can be linked.
func snapshotProcs() (map[int]int, map[int]string) {
	parents, exes := map[int]int{}, map[int]string{}
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pp, _ := procStat(pid)
		parents[pid] = pp
		if exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
			exes[pid] = exe
		}
	}
	return parents, exes
}

// procStat returns ppid and comm for a pid.
func procStat(pid int) (int, string) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, ""
	}
	s := string(b)
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return 0, ""
	}
	comm := s[l+1 : r]
	f := strings.Fields(s[r+1:])
	if len(f) < 2 {
		return 0, comm
	}
	pp, _ := strconv.Atoi(f[1])
	return pp, comm
}

// findRoot picks the process whose descendants are "the job": the GitHub
// Actions Runner.Worker if we're under one, else the first ancestor that isn't
// sudo or titra (the shell that asked for tracing).
func findRoot(procs map[int]int) (int, string) {
	if v := os.Getenv("TITRA_TRACE_ROOT_PID"); v != "" {
		n, _ := strconv.Atoi(v)
		_, c := procStat(n)
		return n, c
	}
	var chain []int
	pid := os.Getpid()
	for i := 0; i < 64 && pid > 1; i++ {
		chain = append(chain, pid)
		pid = procs[pid]
		if pid == 0 {
			pid, _ = procStat(chain[len(chain)-1])
		}
	}
	for _, p := range chain {
		if _, c := procStat(p); c == "Runner.Worker" {
			return p, c
		}
	}
	for _, p := range chain[1:] {
		_, c := procStat(p)
		if c != "sudo" && !strings.HasPrefix(c, "titra") {
			return p, c
		}
	}
	return 0, ""
}
