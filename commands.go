package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/dnslog"
	"github.com/ChelateSec/titra/internal/egress"
	"github.com/ChelateSec/titra/internal/guard"
	"github.com/ChelateSec/titra/internal/hook"
	"github.com/ChelateSec/titra/internal/jobctx"
	"github.com/ChelateSec/titra/internal/policy"
	"github.com/ChelateSec/titra/internal/report"
	"github.com/ChelateSec/titra/internal/trace"
)

// buildReport assembles the full Story when a trace state dir is present and
// readable; otherwise it returns the legacy summary. Exactly one of the two
// return values is meaningful (story != nil means use it).
func buildReport(logPath, stateDir string) (*report.Story, report.Summary, error) {
	recs, err := audit.ReadAll(logPath)
	if err != nil {
		return nil, report.Summary{}, err
	}
	ctx := jobctx.FromEnv()

	in := report.Input{
		Records:        recs,
		Context:        ctx,
		AllowedDomains: splitComma(os.Getenv("TITRA_ALLOWED_DOMAINS")),
		ShimTools:      splitComma(os.Getenv("TITRA_TOOLS")),
	}

	// Egress control: refused lookups and rejected connections become records
	// like any other blocked action.
	if mode, allow, dnsLog, ok := loadEgress(stateDir); ok {
		host, _ := os.Hostname()
		dns := egress.DropSearchEchoes(dnslog.ReadLog(dnsLog), egress.SearchDomains(originalResolvConf(stateDir), host))
		var drops []egress.Drop
		if os.Geteuid() == 0 {
			drops = egress.ParseKernelLog(egress.KernelLog())
		} else {
			drops = collectedDrops(stateDir)
		}
		in.Records = append(in.Records, egress.Records(mode, dns, drops)...)
		in.DNS = dns
		in.AllowedDomains = egress.Merge(allow, in.AllowedDomains)
	}

	if stateDir != "" {
		if st, lerr := trace.Load(stateDir); lerr == nil {
			in.State = st
			if st.DNSLog != "" {
				in.DNS = dnslog.ReadLog(st.DNSLog)
			}
			if os.Geteuid() == 0 {
				if evs, cerr := trace.Collect(st); cerr == nil {
					in.Events = evs
				} else {
					in.TraceErr = cerr.Error()
				}
			} else if c := readCollected(); c != nil {
				in.Events, in.TraceErr = c.Events, c.TraceErr // gathered by `titra collect` (disable-sudo)
			} else {
				in.TraceErr = "report not run as root; kernel events not collected"
			}
			s := report.Build(in)
			fillMode(&s)
			return &s, report.Summary{}, nil
		}
	}

	// No trace: still give the richer story shape, just without the trace half,
	// as long as we have job context worth showing. Otherwise legacy summary.
	if ctx.Repo != "" || ctx.Event != "" || len(in.Records) > 0 {
		s := report.Build(in)
		fillMode(&s)
		return &s, report.Summary{}, nil
	}
	return nil, report.Summarize(recs), nil
}

// cmdTrace: `titra trace start|stop|collect`. Needs root.
func cmdTrace(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: titra trace start|stop|collect [flags]")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]
	fs := flag.NewFlagSet("trace", flag.ExitOnError)
	stateDir := fs.String("state", envOr("TITRA_STATE", defaultStateDir()), "trace state dir")
	workspace := fs.String("workspace", os.Getenv("GITHUB_WORKSPACE"), "job workspace to watch for credential files")
	home := fs.String("home", os.Getenv("HOME"), "home dir to watch for credential files")
	dns := fs.Bool("dns", true, "also run the DNS logger so connections show domain names")
	lock := fs.Bool("lock", false, "make audit rules immutable until reboot (ephemeral runners)")
	ghEnv := fs.Bool("github-env", false, "export TITRA_STATE into $GITHUB_ENV for later steps")
	_ = fs.Parse(rest)

	switch sub {
	case "start":
		self, _ := os.Executable()
		if r, err := filepath.EvalSymlinks(self); err == nil {
			self = r
		}
		st, err := trace.Start(trace.Options{
			StateDir: *stateDir, Titra: self, Workspace: *workspace,
			Home: *home, DNS: *dns, Lock: *lock,
		})
		if err != nil {
			// Tracing is a bonus layer: never fail the job because it couldn't start.
			fmt.Fprintf(os.Stderr, "titra: tracing not available: %v\n", err)
			fmt.Fprintln(os.Stderr, "titra: continuing with command-level guarding only.")
			os.Exit(0)
		}
		if *ghEnv {
			if f := os.Getenv("GITHUB_ENV"); f != "" {
				_ = appendEnv(f, "TITRA_STATE", *stateDir)
			}
		}
		fmt.Fprintf(os.Stderr, "titra: tracing the whole job (pid tree under %d). dns=%v watched=%d\n",
			st.RootPID, st.DNS, len(st.Watched))
		for _, w := range st.Warnings {
			fmt.Fprintf(os.Stderr, "titra: %s\n", w)
		}
	case "stop":
		if err := trace.Stop(*stateDir); err != nil {
			fmt.Fprintf(os.Stderr, "titra: %v\n", err)
		}
	case "collect":
		st, err := trace.Load(*stateDir)
		if err != nil {
			fatal(err)
		}
		evs, err := trace.Collect(st)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("titra: collected %d event(s)\n", len(evs))
	default:
		fmt.Fprintf(os.Stderr, "titra: unknown trace subcommand %q\n", sub)
		os.Exit(2)
	}
}

// cmdDNS: `titra dns` runs the logging DNS forwarder (started by trace).
func cmdDNS(args []string) {
	fs := flag.NewFlagSet("dns", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:53", "listen address")
	upstream := fs.String("upstream", "", "upstream resolver (host or host:port)")
	logPath := fs.String("log", "", "path for the JSONL lookup log")
	ready := fs.String("ready", "", "touch this file once both listeners are bound")
	allowFile := fs.String("allow-file", "", "only resolve names listed here (one per line, *.x for subdomains)")
	enforce := fs.Bool("enforce", false, "answer NXDOMAIN for names not on the allowlist (otherwise only mark them)")
	firewall := fs.String("firewall", "", "block|audit: open Titra's firewall for addresses of allowed names")
	_ = fs.Parse(args)
	if *upstream == "" || *logPath == "" {
		fatal(fmt.Errorf("dns: --upstream and --log are required"))
	}
	srv := &dnslog.Server{Listen: *listen, Upstream: *upstream, LogPath: *logPath, Enforce: *enforce}
	if *allowFile != "" {
		raw, err := os.ReadFile(*allowFile)
		if err != nil {
			fatal(err)
		}
		allow := splitLines(string(raw))
		srv.Allow = func(name string) bool { return egress.Allowed(name, allow) }
	}
	if *firewall != "" {
		fw := egress.NewFirewall(*firewall)
		srv.OnAnswer = func(name string, ips []string) {
			for _, ip := range ips {
				if err := fw.AllowIP(ip); err != nil {
					fmt.Fprintf(os.Stderr, "titra dns: allowing %s (%s): %v\n", ip, name, err)
				}
			}
		}
	}
	err := srv.Run(func() {
		if *ready != "" {
			_ = os.WriteFile(*ready, []byte("ok"), 0o644)
		}
	})
	fatal(err)
}

// cmdEgress: `titra egress start|stop` — network egress control (needs root).
func cmdEgress(args []string) {
	if len(args) == 0 || (args[0] != "start" && args[0] != "stop") {
		fmt.Fprintln(os.Stderr, "usage: titra egress start|stop --state DIR [--mode auto|block|audit] [--allow a,b,c]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("egress", flag.ExitOnError)
	stateDir := fs.String("state", os.Getenv("TITRA_STATE"), "state directory (shared with trace)")
	mode := fs.String("mode", "auto", "auto (block in enforce, audit otherwise) | block | audit")
	allowCSV := fs.String("allow", "", "extra allowed domains, comma-separated")
	_ = fs.Parse(args[1:])
	if *stateDir == "" {
		fatal(fmt.Errorf("egress: --state is required"))
	}
	statePath := filepath.Join(*stateDir, "egress.json")

	if args[0] == "stop" {
		for _, c := range egress.TeardownCommands() {
			_ = exec.Command(c[0], c[1:]...).Run()
		}
		var st struct {
			Resolver *trace.Resolver `json:"resolver"`
		}
		if b, err := os.ReadFile(statePath); err == nil && json.Unmarshal(b, &st) == nil {
			trace.StopResolver(st.Resolver)
		}
		restoreNSSwitch(*stateDir)
		fmt.Fprintln(os.Stderr, "titra: egress control stopped")
		return
	}

	if os.Geteuid() != 0 {
		fatal(fmt.Errorf("egress start needs root (run it with sudo)"))
	}
	if err := os.MkdirAll(*stateDir, 0o755); err != nil {
		fatal(err)
	}
	pol, _ := guard.LoadPolicy(guard.ConfigFromEnv())
	m := *mode
	if m == "auto" {
		m = egress.ModeAudit
		if pol != nil && pol.Mode == policy.ModeEnforce {
			m = egress.ModeBlock
		}
	}
	if m != egress.ModeBlock && m != egress.ModeAudit {
		fatal(fmt.Errorf("egress: unknown mode %q", m))
	}
	var polAllow []string
	if pol != nil {
		polAllow = pol.AllowedDomains
	}
	allow := egress.Merge(egress.DefaultAllowed, polAllow, splitComma(*allowCSV))
	allowFile := filepath.Join(*stateDir, "egress-allow.txt")
	if err := os.WriteFile(allowFile, []byte(strings.Join(allow, "\n")+"\n"), 0o644); err != nil {
		fatal(err)
	}

	self, _ := os.Executable()
	fw := egress.NewFirewall(m)
	if err := fw.Prepare(); err != nil {
		fatal(fmt.Errorf("egress: %w", err))
	}
	// Names pinned in /etc/hosts never reach the resolver: open them now.
	if hosts, err := os.ReadFile("/etc/hosts"); err == nil {
		for _, ip := range egress.HostsFileIPs(string(hosts), allow) {
			if err := fw.AllowIP(ip); err != nil {
				fmt.Fprintf(os.Stderr, "titra: egress: allowing %s from /etc/hosts: %v\n", ip, err)
			}
		}
	}
	// glibc's "resolve" NSS module asks systemd-resolved directly, skipping
	// resolv.conf and so Titra's resolver. Route lookups through resolv.conf
	// for the job; stop puts the original file back.
	divertNSSwitch(*stateDir)
	extra := []string{"--allow-file", allowFile, "--firewall", m}
	if m == egress.ModeBlock {
		extra = append(extra, "--enforce")
	}
	res, err := trace.StartResolver(*stateDir, self, extra)
	if err != nil {
		for _, c := range egress.TeardownCommands() {
			_ = exec.Command(c[0], c[1:]...).Run()
		}
		restoreNSSwitch(*stateDir)
		fatal(fmt.Errorf("egress: starting the resolver: %w", err))
	}
	if err := fw.Enable(); err != nil {
		trace.StopResolver(res)
		restoreNSSwitch(*stateDir)
		fatal(fmt.Errorf("egress: %w", err))
	}
	st := map[string]any{"mode": m, "allow": allow, "dns_log": res.LogPath, "resolver": res,
		"started": time.Now().UTC().Format(time.RFC3339)}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(statePath, b, 0o644); err != nil {
		fatal(err)
	}
	verb := "blocking"
	if m == egress.ModeAudit {
		verb = "recording (not blocking)"
	}
	fmt.Fprintf(os.Stderr, "titra: egress control on — %s connections to anything outside %d allowed domains\n", verb, len(allow))
}

const nsswitchPath = "/etc/nsswitch.conf"

func divertNSSwitch(stateDir string) {
	cur, err := os.ReadFile(nsswitchPath)
	if err != nil {
		return
	}
	next, changed := egress.StripNSSResolve(string(cur))
	if !changed {
		return
	}
	bak := filepath.Join(stateDir, "nsswitch.conf.orig")
	if err := os.WriteFile(bak, cur, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "titra: egress: can't back up %s: %v\n", nsswitchPath, err)
		return
	}
	tmp := nsswitchPath + ".titra"
	if err := os.WriteFile(tmp, []byte(next), 0o644); err == nil {
		err = os.Rename(tmp, nsswitchPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "titra: egress: can't update %s: %v\n", nsswitchPath, err)
		}
	}
}

func restoreNSSwitch(stateDir string) {
	bak := filepath.Join(stateDir, "nsswitch.conf.orig")
	b, err := os.ReadFile(bak)
	if err != nil {
		return
	}
	if err := os.WriteFile(nsswitchPath, b, 0o644); err == nil {
		_ = os.Remove(bak)
	}
}

// originalResolvConf is resolv.conf as it was before Titra pointed it at its
// own resolver (saved in the egress state), or the current file.
func originalResolvConf(stateDir string) string {
	var st struct {
		Resolver *trace.Resolver `json:"resolver"`
	}
	if b, err := os.ReadFile(filepath.Join(stateDir, "egress.json")); err == nil && json.Unmarshal(b, &st) == nil &&
		st.Resolver != nil && st.Resolver.Backup != nil {
		return st.Resolver.Backup.Content
	}
	b, _ := os.ReadFile("/etc/resolv.conf")
	return string(b)
}

// loadEgress reads the egress state left by `titra egress start`, if any.
func loadEgress(stateDir string) (mode string, allow []string, dnsLog string, ok bool) {
	if stateDir == "" {
		return "", nil, "", false
	}
	b, err := os.ReadFile(filepath.Join(stateDir, "egress.json"))
	if err != nil {
		return "", nil, "", false
	}
	var st struct {
		Mode   string   `json:"mode"`
		Allow  []string `json:"allow"`
		DNSLog string   `json:"dns_log"`
	}
	if json.Unmarshal(b, &st) != nil {
		return "", nil, "", false
	}
	return st.Mode, st.Allow, st.DNSLog, true
}

// collectedDrops reads firewall drops gathered by the root-only collector
// (used when disable-sudo took sudo away from the post step).
func collectedDrops(stateDir string) []egress.Drop {
	b, err := os.ReadFile(collectedPath(stateDir))
	if err != nil {
		return nil
	}
	var c struct {
		KernelLog string `json:"kernel_log"`
	}
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return egress.ParseKernelLog(c.KernelLog)
}

// Paths used by disable-sudo. The collector runs as root with no arguments, so
// everything it reads and writes is fixed and root-owned: nothing in the job
// can point it at another file.
const (
	rootStateDir  = "/etc/titra"
	collectedFile = "/var/lib/titra/collected.json"
)

func collectedPath(string) string { return collectedFile }

type collected struct {
	Events    []trace.Event `json:"events,omitempty"`
	TraceErr  string        `json:"trace_err,omitempty"`
	KernelLog string        `json:"kernel_log,omitempty"`
}

func readCollected() *collected {
	b, err := os.ReadFile(collectedFile)
	if err != nil {
		return nil
	}
	var c collected
	if json.Unmarshal(b, &c) != nil {
		return nil
	}
	return &c
}

// cmdCollect: `titra collect` gathers the root-only evidence (kernel audit
// events, firewall log) for a job whose sudo was disabled. It takes no
// arguments by design; sudoers allows exactly this command line.
func cmdCollect(args []string) {
	if len(args) != 0 {
		fatal(fmt.Errorf("collect takes no arguments"))
	}
	if os.Geteuid() != 0 {
		fatal(fmt.Errorf("collect needs root"))
	}
	var c collected
	if st, err := trace.Load(rootStateDir); err == nil {
		if evs, cerr := trace.Collect(st); cerr == nil {
			c.Events = evs
		} else {
			c.TraceErr = cerr.Error()
		}
	}
	c.KernelLog = egress.KernelLog()
	b, _ := json.Marshal(c)
	if err := os.MkdirAll(filepath.Dir(collectedFile), 0o755); err != nil {
		fatal(err)
	}
	tmp := collectedFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		fatal(err)
	}
	if err := os.Rename(tmp, collectedFile); err != nil {
		fatal(err)
	}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

// cmdHook: `titra hook claude` — the Claude Code PreToolUse hook.
func cmdHook(args []string) { hook.Main(args) }

func defaultStateDir() string {
	if rt := os.Getenv("RUNNER_TEMP"); rt != "" {
		return filepath.Join(rt, "titra-trace")
	}
	return filepath.Join(os.TempDir(), "titra-trace")
}

func appendEnv(path, k, v string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s=%s\n", k, v)
	return err
}

// fillMode records the mode the guard was actually enforcing, even when the job
// produced no guarded actions, so the server can spot a weakened org policy.
func fillMode(s *report.Story) {
	if s.Mode != "" {
		return
	}
	if p, _ := guard.LoadPolicy(guard.ConfigFromEnv()); p != nil {
		s.Mode = string(p.Mode)
	}
}
