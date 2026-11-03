package report

import (
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/dnslog"
	"github.com/ChelateSec/titra/internal/egress"
	"github.com/ChelateSec/titra/internal/jobctx"
	"github.com/ChelateSec/titra/internal/trace"
)

// Story is the full account of one job: who started it, which agent ran, what
// it tried, what was stopped, and everything else the job touched that the
// shims alone could not see.
type Story struct {
	Generated string         `json:"generated,omitempty"` // RFC3339 when the report was built
	Context   jobctx.Context `json:"context"`
	Mode      string         `json:"mode"`
	Status    string         `json:"status"` // blocked | warning | clean

	Actions    []audit.Record `json:"actions"`
	Blocked    []audit.Record `json:"blocked"`
	WouldBlock []audit.Record `json:"would_block"`
	AgentCalls int            `json:"agent_calls"`

	Traced    bool       `json:"traced"`
	TraceNote string     `json:"trace_note,omitempty"`
	Processes int        `json:"processes"`
	Bypasses  []Bypass   `json:"bypasses,omitempty"`
	Egress    []Dest     `json:"egress,omitempty"`
	CredReads []FileRead `json:"credential_reads,omitempty"`
}

// Bypass is a guarded tool that ran straight from disk, never through Titra.
type Bypass struct {
	Tool string `json:"tool"`
	Cmd  string `json:"cmd"`
	Exe  string `json:"exe"`
}

// Dest is one network destination the job reached.
type Dest struct {
	Host     string   `json:"host"`
	IP       string   `json:"ip"`
	Port     int      `json:"port"`
	Procs    []string `json:"procs"`
	N        int      `json:"n"`
	Expected bool     `json:"expected"`
}

// FileRead is a credential file read by something other than its owner tool.
type FileRead struct {
	Path string `json:"path"`
	Proc string `json:"proc"`
}

// Input is everything Build needs to assemble a Story.
type Input struct {
	Records        []audit.Record
	Context        jobctx.Context
	State          *trace.State // nil when tracing was off
	Events         []trace.Event
	DNS            []dnslog.Entry
	AllowedDomains []string
	ShimTools      []string
	TraceErr       string
}

// DefaultAllowed is where CI jobs legitimately connect: source hosting and the
// package registries and model APIs a build normally needs. Anything else is
// worth a maintainer's glance.
// DefaultAllowed is where CI jobs legitimately connect. It is the same list
// egress control enforces, so the report and the firewall never disagree.
var DefaultAllowed = egress.DefaultAllowed

// bypassTools are the high-value commands whose direct (non-shim) use matters.
var bypassTools = map[string]bool{
	"git": true, "gh": true, "curl": true, "wget": true,
	"npm": true, "pnpm": true, "yarn": true, "pip": true, "pip3": true,
}

// credOwner maps a credential file's basename to the tools allowed to read it.
// A read by anything else is flagged.
var credOwner = map[string][]string{
	"config":            {"git", "gh"}, // .git/config
	".gitconfig":        {"git", "gh"},
	".git-credentials":  {"git"},
	".npmrc":            {"npm", "node", "npx", "pnpm", "yarn"},
	".pypirc":           {"twine", "pip", "python", "python3"},
	"config.json":       {"docker", "buildx", "docker-buildx", "containerd"},
	"hosts.yml":         {"gh"},
	"credentials":       {"aws", "python", "python3"},
	".credentials.json": {"claude", "node"},
}

// Build assembles the story from the log, the job context, and (if tracing was
// on) the kernel events and DNS log.
func Build(in Input) Story {
	s := Story{Generated: time.Now().UTC().Format(time.RFC3339), Context: in.Context, Actions: in.Records}

	for _, r := range in.Records {
		if s.Mode == "" && r.Mode != "" {
			s.Mode = r.Mode
		}
		switch r.Verdict {
		case "block":
			s.Blocked = append(s.Blocked, r)
		case "would-block":
			s.WouldBlock = append(s.WouldBlock, r)
		}
		if r.Source == "claude-code" {
			s.AgentCalls++
			s.Context.AddAgent("Claude Code")
		}
	}
	sortBySev(s.Blocked)
	sortBySev(s.WouldBlock)

	if in.State != nil {
		s.Traced = in.TraceErr == ""
		if in.TraceErr != "" {
			s.TraceNote = in.TraceErr
		}
		s.fromTrace(in)
	} else {
		s.TraceNote = "tracing off — only commands through Titra's shims are shown"
	}

	switch {
	case len(s.Blocked) > 0:
		s.Status = "blocked"
	case s.Warnings() > 0:
		s.Status = "warning"
	default:
		s.Status = "clean"
	}
	return s
}

// Warnings counts findings that did not block but a maintainer should see.
func (s Story) Warnings() int {
	n := len(s.WouldBlock) + len(s.Bypasses) + len(s.CredReads)
	for _, d := range s.Egress {
		if !d.Expected {
			n++
		}
	}
	return n
}

// Unexpected returns egress destinations outside the allowlist.
func (s Story) Unexpected() []Dest {
	var out []Dest
	for _, d := range s.Egress {
		if !d.Expected {
			out = append(out, d)
		}
	}
	return out
}

func (s *Story) fromTrace(in Input) {
	// Map resolved IPs back to the names that produced them.
	nameOf := map[string]string{}
	for _, e := range in.DNS {
		for _, ip := range e.IPs {
			if _, seen := nameOf[ip]; !seen {
				nameOf[ip] = e.Name
			}
		}
	}

	allow := append(append([]string{}, DefaultAllowed...), in.AllowedDomains...)
	procs := map[int]bool{}
	dests := map[string]*Dest{}

	for _, e := range in.Events {
		procs[e.PID] = true
		switch e.Kind {
		case "exec":
			s.checkBypass(e)
		case "connect":
			s.addDest(dests, e, nameOf, allow)
		case "file":
			s.checkCredRead(e)
		}
	}
	s.Processes = len(procs)

	for _, d := range dests {
		sort.Strings(d.Procs)
		s.Egress = append(s.Egress, *d)
	}
	sort.Slice(s.Egress, func(i, j int) bool {
		if s.Egress[i].Expected != s.Egress[j].Expected {
			return !s.Egress[i].Expected // unexpected first
		}
		return s.Egress[i].Host < s.Egress[j].Host
	})
	dedupBypass(&s.Bypasses)
	dedupCred(&s.CredReads)
}

// checkBypass flags a guarded tool that ran straight from disk. Titra's shims
// exec the real binary, so a shim-routed run shows the real path too — we only
// flag it when the parent chain never passed through a shim, which in practice
// means the exec's own argv0 is an absolute/real path to the tool rather than a
// bare name resolved via the shim dir.
func (s *Story) checkBypass(e trace.Event) {
	base := filepath.Base(e.Exe)
	if !bypassTools[base] {
		return
	}
	// A shim invocation execs the real tool with argv0 = the real path, so the
	// real tool always appears. The signal of a *bypass* is an exec whose own
	// command used an absolute path or ./ to the binary, skipping PATH (and so
	// the shim dir) entirely.
	if len(e.Args) == 0 {
		return
	}
	argv0 := e.Args[0]
	if strings.ContainsRune(argv0, '/') && base == filepath.Base(argv0) {
		s.Bypasses = append(s.Bypasses, Bypass{
			Tool: base,
			Cmd:  strings.Join(e.Args, " "),
			Exe:  e.Exe,
		})
	}
}

func (s *Story) addDest(dests map[string]*Dest, e trace.Event, nameOf map[string]string, allow []string) {
	host := nameOf[e.Addr]
	key := host
	if key == "" {
		key = e.Addr
	}
	d := dests[key]
	if d == nil {
		d = &Dest{Host: host, IP: e.Addr, Port: e.Port, Expected: isAllowed(host, allow) || isLocal(e.Addr)}
		dests[key] = d
	}
	d.N++
	proc := filepath.Base(e.Exe)
	if proc == "" {
		proc = e.Comm
	}
	if !contains(d.Procs, proc) {
		d.Procs = append(d.Procs, proc)
	}
}

func (s *Story) checkCredRead(e trace.Event) {
	base := filepath.Base(e.Path)
	owners, known := credOwner[base]
	if !known {
		owners = []string{} // unknown watched file: any read is notable
	}
	proc := filepath.Base(e.Exe)
	if proc == "" {
		proc = e.Comm
	}
	// The owning tool reading its own credential file is normal.
	for _, o := range owners {
		if proc == o {
			return
		}
	}
	// Titra itself and the runner reading .git/config at checkout are normal.
	if strings.HasPrefix(proc, "titra") || proc == "Runner.Worker" || proc == "node" && base == "config" {
		return
	}
	s.CredReads = append(s.CredReads, FileRead{Path: e.Path, Proc: proc})
}

// isAllowed reports whether host matches the allowlist (supports one leading
// "*." wildcard per pattern).
func isAllowed(host string, allow []string) bool {
	if host == "" {
		return false // a raw-IP connection with no name is not "known good"
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range allow {
		p = strings.ToLower(p)
		if strings.HasPrefix(p, "*.") {
			suf := p[1:] // ".example.com"
			if strings.HasSuffix(host, suf) || host == p[2:] {
				return true
			}
			continue
		}
		if host == p {
			return true
		}
	}
	return false
}

func isLocal(ip string) bool {
	return strings.HasPrefix(ip, "127.") || ip == "::1" || strings.HasPrefix(ip, "169.254.") ||
		strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, "172.")
}

func contains(ss []string, v string) bool {
	for _, s := range ss {
		if s == v {
			return true
		}
	}
	return false
}

func sortBySev(recs []audit.Record) {
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	sort.SliceStable(recs, func(i, j int) bool { return rank[recs[i].Severity] > rank[recs[j].Severity] })
}

func dedupBypass(b *[]Bypass) {
	seen := map[string]bool{}
	var out []Bypass
	for _, x := range *b {
		if seen[x.Cmd] {
			continue
		}
		seen[x.Cmd] = true
		out = append(out, x)
	}
	*b = out
}

func dedupCred(c *[]FileRead) {
	seen := map[string]bool{}
	var out []FileRead
	for _, x := range *c {
		k := x.Proc + "\x00" + x.Path
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, x)
	}
	*c = out
}
