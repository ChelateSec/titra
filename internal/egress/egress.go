// Package egress controls where a CI job may connect. It is the boundary that
// holds even when an agent (or attacker code) skips every command guard: a
// `curl`, a Python socket, a raw IP, a hand-rolled DNS lookup all leave the
// machine through the same network stack.
//
// Two parts work together:
//
//  1. The job's resolver (titra's DNS logger) answers only names on the
//     allowlist. Anything else gets NXDOMAIN, so most tools fail fast with
//     "could not resolve host".
//  2. A firewall chain rejects every new outbound connection from the job's
//     user unless its destination IP was handed out by that resolver for an
//     allowed name. A hardcoded IP or a lookup against another DNS server
//     therefore goes nowhere either.
//
// In audit mode the same decisions are made but only recorded: DNS answers
// everything and the firewall logs instead of rejecting.
package egress

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/dnslog"
)

// Modes.
const (
	ModeBlock = "block"
	ModeAudit = "audit"
)

// Rule IDs that appear in reports.
const (
	RuleID      = "egress-not-allowed"
	LogPrefix   = "titra-egress-block: "
	AuditPrefix = "titra-egress-audit: "
	chain       = "TITRA_EGRESS"
	allowChain  = "TITRA_ALLOW"
)

// DefaultAllowed is where CI jobs legitimately connect: GitHub and the Actions
// service, package registries, and the model APIs agents call. Customers add
// their own with the allowed-domains input or the policy's allowed_domains.
var DefaultAllowed = []string{
	// GitHub and the Actions service (the runner itself needs these).
	"github.com", "*.github.com", "*.githubusercontent.com", "*.githubassets.com",
	"*.actions.githubusercontent.com", "*.blob.core.windows.net", "ghcr.io", "*.ghcr.io",
	"*.pkg.github.com", "codeload.github.com", "objects.githubusercontent.com",
	"*.githubapp.com", // GitHub-hosted runner infrastructure (hosted-compute-*)
	// Package registries and toolchains.
	"registry.npmjs.org", "*.npmjs.org", "registry.yarnpkg.com", "*.yarnpkg.com", "nodejs.org", "*.nodejs.org", "bun.sh",
	"pypi.org", "files.pythonhosted.org", "*.pythonhosted.org",
	"proxy.golang.org", "sum.golang.org", "storage.googleapis.com", "go.dev", "golang.org",
	"crates.io", "*.crates.io", "static.crates.io", "static.rust-lang.org",
	"rubygems.org", "*.rubygems.org", "repo.maven.apache.org", "repo1.maven.org",
	"api.nuget.org", "*.nuget.org",
	"*.docker.io", "*.docker.com", "registry-1.docker.io", "auth.docker.io",
	"*.ubuntu.com", "*.debian.org", "packages.microsoft.com", "*.microsoft.com", "*.azureedge.net",
	// Model APIs and the agents' own services.
	"api.anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "sentry.io", "*.sentry.io",
	"api.openai.com", "generativelanguage.googleapis.com", "*.googleapis.com",
}

// Allowed reports whether host matches the allowlist. "*.example.com" matches
// example.com and every subdomain; anything else must match exactly.
func Allowed(host string, allow []string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	for _, p := range allow {
		p = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(p), "."))
		if p == "" {
			continue
		}
		if strings.HasPrefix(p, "*.") {
			if host == p[2:] || strings.HasSuffix(host, p[1:]) {
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

// Merge combines allowlists, dropping blanks and duplicates, in a stable order.
func Merge(lists ...[]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lists {
		for _, d := range l {
			d = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(d), "."))
			if d != "" && !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// Firewall manages the iptables/ip6tables chains. Run executes one command; it
// is swappable so tests can capture the commands instead of running them.
type Firewall struct {
	Mode       string   // block | audit
	ExemptUIDs []string // users whose traffic is never filtered (root, the system resolver)
	Run        func(argv []string) error

	mu      sync.Mutex
	allowed map[string]*pending
	noV6    bool
}

// NewFirewall returns a firewall that runs real commands.
func NewFirewall(mode string) *Firewall {
	return &Firewall{Mode: mode, ExemptUIDs: SystemUIDs(), Run: runCmd}
}

// SystemUIDs are the users exempt from filtering: root (Titra's own resolver
// runs as root and forwards upstream) and systemd-resolved if present. The job
// runs as a regular user, so it is always filtered. Without disable-sudo the
// job can become root; that is the documented limit disable-sudo closes.
func SystemUIDs() []string {
	uids := []string{"0"}
	for _, name := range []string{"systemd-resolve", "systemd-network"} {
		if u, err := user.Lookup(name); err == nil {
			uids = append(uids, u.Uid)
		}
	}
	return uids
}

// SetupCommands returns the commands that install the chains, in order. The
// v6 commands come second and are allowed to fail (some runners lack ip6tables).
func (f *Firewall) SetupCommands() (v4, v6 [][]string) {
	for _, family := range []string{"iptables", "ip6tables"} {
		var cmds [][]string
		add := func(args ...string) { cmds = append(cmds, append([]string{family, "-w"}, args...)) }
		add("-N", allowChain)
		add("-N", chain)
		add("-A", chain, "-o", "lo", "-j", "ACCEPT")
		add("-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
		for _, uid := range f.ExemptUIDs {
			add("-A", chain, "-m", "owner", "--uid-owner", uid, "-j", "ACCEPT")
		}
		// The job may only use Titra's resolver. Direct DNS (53) and DNS over
		// TLS (853) to anything else is refused before the allowlist is even
		// consulted, so an allowed address that happens to run a DNS server
		// can't be used to look up (or leak through) arbitrary names.
		dnsVerdict := []string{"-j", "REJECT"}
		if f.Mode != ModeBlock {
			dnsVerdict = []string{"-j", "LOG", "--log-prefix", AuditPrefix, "--log-uid"}
		}
		for _, p := range [][]string{{"udp", "53"}, {"tcp", "53"}, {"tcp", "853"}} {
			add(append([]string{"-A", chain, "-p", p[0], "--dport", p[1]}, dnsVerdict...)...)
		}
		add("-A", chain, "-j", allowChain)
		if f.Mode == ModeBlock {
			add("-A", chain, "-m", "limit", "--limit", "60/min", "--limit-burst", "60",
				"-j", "LOG", "--log-prefix", LogPrefix, "--log-uid")
			add("-A", chain, "-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset")
			reject := "icmp-port-unreachable"
			if family == "ip6tables" {
				reject = "icmp6-port-unreachable"
			}
			add("-A", chain, "-j", "REJECT", "--reject-with", reject)
		} else {
			add("-A", chain, "-m", "conntrack", "--ctstate", "NEW", "-m", "limit", "--limit", "60/min",
				"--limit-burst", "60", "-j", "LOG", "--log-prefix", AuditPrefix, "--log-uid")
		}
		add("-I", "OUTPUT", "1", "-j", chain)
		if family == "iptables" {
			v4 = cmds
		} else {
			v6 = cmds
		}
	}
	return v4, v6
}

// Prepare creates the chains without hooking them into OUTPUT yet, so the
// resolver can start adding allowed addresses before anything is filtered.
// An IPv4 failure is fatal (no protection). IPv6 is best effort: hosted runners
// have no IPv6 route out, and some images lack ip6tables.
func (f *Firewall) Prepare() error {
	v4, v6 := f.SetupCommands()
	for _, c := range v4[:len(v4)-1] {
		if err := f.Run(c); err != nil {
			return fmt.Errorf("%s: %w", strings.Join(c, " "), err)
		}
	}
	for _, c := range v6[:len(v6)-1] {
		if err := f.Run(c); err != nil {
			f.noV6 = true
			break
		}
	}
	return nil
}

// Enable hooks the chains into OUTPUT: from here on, filtering is live.
func (f *Firewall) Enable() error {
	v4, v6 := f.SetupCommands()
	if err := f.Run(v4[len(v4)-1]); err != nil {
		return fmt.Errorf("enabling the firewall: %w", err)
	}
	if !f.noV6 {
		_ = f.Run(v6[len(v6)-1])
	}
	return nil
}

// Setup is Prepare followed by Enable.
func (f *Firewall) Setup() error {
	if err := f.Prepare(); err != nil {
		return err
	}
	return f.Enable()
}

// AllowIP opens the firewall for one address the resolver handed out for an
// allowed name. Idempotent and safe to call concurrently.
func (f *Firewall) AllowIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("not an IP: %q", ip)
	}
	// The resolver calls this for every answer, often for the same address
	// from parallel lookups. The answer is only relayed after this returns, so
	// a caller must never return before the rule exists: a second lookup waits
	// for the first one's iptables call instead of skipping it. A failed call
	// is forgotten so the next lookup retries.
	f.mu.Lock()
	if f.allowed == nil {
		f.allowed = map[string]*pending{}
	}
	if p := f.allowed[ip]; p != nil {
		f.mu.Unlock()
		<-p.done
		if p.err == nil {
			return nil
		}
		return f.AllowIP(ip) // the earlier attempt failed and was forgotten; try again
	}
	p := &pending{done: make(chan struct{})}
	f.allowed[ip] = p
	f.mu.Unlock()

	family := "iptables"
	if parsed.To4() == nil {
		family = "ip6tables"
	}
	p.err = f.Run([]string{family, "-w", "-A", allowChain, "-d", ip, "-j", "ACCEPT"})
	if p.err != nil {
		f.mu.Lock()
		delete(f.allowed, ip)
		f.mu.Unlock()
	}
	close(p.done)
	return p.err
}

type pending struct {
	done chan struct{}
	err  error
}

// HostsFileIPs returns the addresses /etc/hosts pins for allowed names. Those
// names never reach the resolver, so the firewall has to open them up front.
func HostsFileIPs(hosts string, allow []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, line := range strings.Split(hosts, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		ip := net.ParseIP(f[0])
		if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || seen[f[0]] {
			continue
		}
		for _, name := range f[1:] {
			if Allowed(name, allow) {
				seen[f[0]] = true
				out = append(out, f[0])
				break
			}
		}
	}
	return out
}

// StripNSSResolve removes systemd-resolved's NSS module ("resolve" and its
// [action] options) from the hosts line of nsswitch.conf. With it, glibc asks
// systemd-resolved directly and never reads /etc/resolv.conf, so lookups would
// skip Titra's resolver and its answers would never open the firewall. It
// reports whether anything changed; "dns" is kept (or added) so names still
// resolve through resolv.conf.
func StripNSSResolve(conf string) (string, bool) {
	lines := strings.Split(conf, "\n")
	changed := false
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "hosts:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(t, "hosts:"))
		var keep []string
		hasDNS := false
		for j := 0; j < len(fields); j++ {
			if fields[j] == "resolve" {
				changed = true
				for j+1 < len(fields) && strings.HasPrefix(fields[j+1], "[") {
					j++
				}
				continue
			}
			if fields[j] == "dns" {
				hasDNS = true
			}
			keep = append(keep, fields[j])
		}
		if !changed {
			return conf, false
		}
		if !hasDNS {
			keep = append(keep, "dns")
		}
		lines[i] = "hosts: " + strings.Join(keep, " ")
	}
	return strings.Join(lines, "\n"), changed
}

// State is what `titra egress start` records for the report and for stop.
type State struct {
	Mode     string   `json:"mode"`
	Allow    []string `json:"allow"`
	DNSLog   string   `json:"dns_log"`
	Resolver any      `json:"resolver,omitempty"`
	Started  string   `json:"started"`
}

// TeardownCommands removes everything Setup added (for self-hosted runners).
func TeardownCommands() [][]string {
	var cmds [][]string
	for _, family := range []string{"iptables", "ip6tables"} {
		cmds = append(cmds,
			[]string{family, "-w", "-D", "OUTPUT", "-j", chain},
			[]string{family, "-w", "-F", chain},
			[]string{family, "-w", "-X", chain},
			[]string{family, "-w", "-F", allowChain},
			[]string{family, "-w", "-X", allowChain},
		)
	}
	return cmds
}

func runCmd(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Drop is one connection the firewall rejected (or would have, in audit mode).
type Drop struct {
	IP    string
	Port  int
	Proto string
	UID   string
	Audit bool
}

// ParseKernelLog extracts Titra's firewall log lines from dmesg/journal text.
func ParseKernelLog(text string) []Drop {
	var out []Drop
	sc := bufio.NewScanner(strings.NewReader(text))
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		audit := strings.Contains(line, strings.TrimSpace(AuditPrefix))
		if !audit && !strings.Contains(line, strings.TrimSpace(LogPrefix)) {
			continue
		}
		d := Drop{Audit: audit}
		for _, f := range strings.Fields(line) {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				continue
			}
			switch k {
			case "DST":
				d.IP = v
			case "DPT":
				d.Port, _ = strconv.Atoi(v)
			case "PROTO":
				d.Proto = strings.ToLower(v)
			case "UID":
				d.UID = v
			}
		}
		if d.IP != "" {
			out = append(out, d)
		}
	}
	return out
}

// KernelLog reads the kernel ring buffer (needs root). Empty on failure.
func KernelLog() string {
	out, err := exec.Command("dmesg").Output()
	if err != nil {
		return ""
	}
	return string(out)
}

// Records turns the resolver's refusals and the firewall's drops into the
// same records every other Titra decision uses, so reports, checks, the
// dashboard and fail-on treat a blocked connection like a blocked command.
// SearchDomains are the suffixes the system resolver appends to a name when a
// lookup fails: the search/domain lines of the original resolv.conf, the
// host's own domain, and Azure's internal DNS zone (GitHub-hosted runners).
func SearchDomains(resolvConf, hostname string) []string {
	out := []string{"internal.cloudapp.net"}
	for _, line := range strings.Split(resolvConf, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && (f[0] == "search" || f[0] == "domain") {
			out = append(out, f[1:]...)
		}
	}
	if i := strings.IndexByte(hostname, '.'); i > 0 {
		out = append(out, hostname[i+1:])
	}
	return Merge(out)
}

// DropSearchEchoes removes lookups that are only the resolver retrying a
// refused name with a search domain appended ("x.com" then
// "x.com.abc.internal.cloudapp.net"). They were refused too, but reporting
// them would list every blocked destination twice under a confusing name.
func DropSearchEchoes(dns []dnslog.Entry, suffixes []string) []dnslog.Entry {
	queried := map[string]bool{}
	for _, e := range dns {
		queried[e.Name] = true
	}
	isEcho := func(name string) bool {
		for _, suf := range suffixes {
			suf = strings.ToLower(strings.Trim(suf, "."))
			if suf == "" || !strings.HasSuffix(name, "."+suf) {
				continue
			}
			rest := strings.TrimSuffix(name, "."+suf) // may still carry a host-specific label
			for {
				if queried[rest] && rest != name {
					return true
				}
				i := strings.LastIndexByte(rest, '.')
				if i < 0 {
					break
				}
				rest = rest[:i]
			}
		}
		return false
	}
	out := dns[:0:0]
	for _, e := range dns {
		if e.Denied && isEcho(e.Name) {
			continue
		}
		out = append(out, e)
	}
	return out
}

func Records(mode string, dns []dnslog.Entry, drops []Drop) []audit.Record {
	verdict := "block"
	if mode != ModeBlock {
		verdict = "would-block"
	}
	nameOf := map[string]string{}
	for _, e := range dns {
		for _, ip := range e.IPs {
			nameOf[ip] = e.Name
		}
	}
	type key struct{ host, port string }
	seen := map[key]bool{}
	var out []audit.Record
	add := func(host, port, how string, time string) {
		k := key{host, port}
		if seen[k] {
			return
		}
		seen[k] = true
		target := host
		if port != "" {
			target = net.JoinHostPort(host, port)
		}
		out = append(out, audit.Record{
			Time: time, Tool: "network", Args: []string{target}, Verdict: verdict,
			RuleID: RuleID, Severity: "high", Mode: mode, Source: "network",
			Reason: "destination is not on the allowlist (" + how + ")",
			Repo:   os.Getenv("GITHUB_REPOSITORY"), RunID: os.Getenv("GITHUB_RUN_ID"),
			Workflow: os.Getenv("GITHUB_WORKFLOW"), Actor: os.Getenv("GITHUB_ACTOR"),
		})
	}
	how := "DNS lookup refused"
	if mode != ModeBlock {
		how = "looked up"
	}
	for _, e := range dns {
		if e.Denied {
			add(e.Name, "", how, e.Time.UTC().Format("2006-01-02T15:04:05Z"))
		}
	}
	for _, d := range drops {
		if (mode == ModeBlock) == d.Audit {
			continue // a stale line from the other mode
		}
		host := d.IP
		if n := nameOf[d.IP]; n != "" {
			host = n
		}
		port := ""
		if d.Port > 0 {
			port = strconv.Itoa(d.Port)
		}
		add(host, port, "connection rejected by firewall", "")
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Args[0] < out[j].Args[0] })
	return out
}
