package egress

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ChelateSec/titra/internal/dnslog"
)

func TestAllowed(t *testing.T) {
	allow := []string{"github.com", "*.github.com", "api.anthropic.com", "*.npmjs.org"}
	yes := []string{"github.com", "api.github.com", "API.GitHub.com.", "a.b.github.com", "api.anthropic.com", "registry.npmjs.org", "npmjs.org", "localhost"}
	no := []string{"evilgithub.com", "github.com.evil.io", "anthropic.com", "x.api.anthropic.com", "attacker.example", "", "1.1.1.1", "npmjs.org.evil.io"}
	for _, h := range yes {
		if !Allowed(h, allow) {
			t.Errorf("%q should be allowed", h)
		}
	}
	for _, h := range no {
		if Allowed(h, allow) {
			t.Errorf("%q must not be allowed", h)
		}
	}
}

func TestMerge(t *testing.T) {
	got := Merge([]string{"A.com", "b.com"}, []string{"a.com.", " ", "c.com"})
	if strings.Join(got, ",") != "a.com,b.com,c.com" {
		t.Fatalf("merge: %v", got)
	}
}

func TestBlockRules(t *testing.T) {
	f := &Firewall{Mode: ModeBlock, ExemptUIDs: []string{"0", "102"}}
	v4, v6 := f.SetupCommands()
	all := join(v4)
	for _, want := range []string{
		"iptables -w -A TITRA_EGRESS -o lo -j ACCEPT",
		"--ctstate ESTABLISHED,RELATED -j ACCEPT",
		"--uid-owner 0 -j ACCEPT", "--uid-owner 102 -j ACCEPT",
		"-A TITRA_EGRESS -j TITRA_ALLOW",
		"--log-prefix " + LogPrefix,
		"-p tcp -j REJECT --reject-with tcp-reset",
		"-j REJECT --reject-with icmp-port-unreachable",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("v4 rules missing %q:\n%s", want, all)
		}
	}
	// The OUTPUT hook must be last, so nothing is filtered before the chain is complete.
	if last := strings.Join(v4[len(v4)-1], " "); last != "iptables -w -I OUTPUT 1 -j TITRA_EGRESS" {
		t.Fatalf("last v4 command = %q", last)
	}
	if !strings.Contains(join(v6), "icmp6-port-unreachable") {
		t.Fatal("v6 must reject with icmp6")
	}
	// Direct DNS is refused before the allowlist; everything else is checked
	// against the allowlist before the final reject.
	dns := strings.Index(all, "-p udp --dport 53 -j REJECT")
	allowJump := strings.Index(all, "-A TITRA_EGRESS -j TITRA_ALLOW")
	final := strings.Index(all, "-p tcp -j REJECT --reject-with tcp-reset")
	if dns < 0 || !(dns < allowJump && allowJump < final) {
		t.Fatalf("order must be: refuse direct DNS, allowlist, reject the rest (%d %d %d)", dns, allowJump, final)
	}
	if !strings.Contains(all, "-p tcp --dport 853 -j REJECT") {
		t.Fatal("DNS over TLS must be refused too")
	}
}

func TestAuditRulesNeverReject(t *testing.T) {
	f := &Firewall{Mode: ModeAudit, ExemptUIDs: []string{"0"}}
	v4, v6 := f.SetupCommands()
	all := join(v4) + join(v6)
	if strings.Contains(all, "REJECT") || strings.Contains(all, "DROP") {
		t.Fatalf("audit mode must not reject:\n%s", all)
	}
	if !strings.Contains(all, AuditPrefix) {
		t.Fatal("audit mode must log")
	}
}

func TestPrepareEnableOrder(t *testing.T) {
	var ran []string
	f := &Firewall{Mode: ModeBlock, ExemptUIDs: []string{"0"}, Run: func(a []string) error { ran = append(ran, strings.Join(a, " ")); return nil }}
	if err := f.Prepare(); err != nil {
		t.Fatal(err)
	}
	for _, c := range ran {
		if strings.Contains(c, "OUTPUT") {
			t.Fatalf("Prepare must not hook OUTPUT yet: %s", c)
		}
	}
	_ = f.AllowIP("140.82.112.3") // resolver adds addresses between Prepare and Enable
	_ = f.Enable()
	if !strings.Contains(ran[len(ran)-2], "-I OUTPUT 1 -j TITRA_EGRESS") || !strings.HasPrefix(ran[len(ran)-2], "iptables ") {
		t.Fatalf("Enable should hook v4 OUTPUT: %v", ran[len(ran)-3:])
	}
}

func TestAllowIPFamilyAndDedup(t *testing.T) {
	var ran []string
	f := &Firewall{Run: func(a []string) error { ran = append(ran, strings.Join(a, " ")); return nil }}
	_ = f.AllowIP("140.82.112.3")
	_ = f.AllowIP("140.82.112.3")
	_ = f.AllowIP("2606:50c0:8000::153")
	if err := f.AllowIP("not-an-ip; rm -rf /"); err == nil {
		t.Fatal("garbage must be rejected, never passed to iptables")
	}
	want := []string{
		"iptables -w -A TITRA_ALLOW -d 140.82.112.3 -j ACCEPT",
		"ip6tables -w -A TITRA_ALLOW -d 2606:50c0:8000::153 -j ACCEPT",
	}
	if strings.Join(ran, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v", ran)
	}
}

const dmesg = `[  101.1] some other kernel line
[  102.2] titra-egress-block: IN= OUT=eth0 SRC=10.1.0.4 DST=1.1.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=1 DF PROTO=TCP SPT=40712 DPT=443 WINDOW=64240 RES=0x00 SYN URGP=0 UID=1001 GID=1001
[  103.3] titra-egress-block: IN= OUT=eth0 SRC=10.1.0.4 DST=203.0.113.9 LEN=60 PROTO=UDP SPT=5353 DPT=53 LEN=40 UID=1001 GID=1001
[  104.4] titra-egress-audit: IN= OUT=eth0 SRC=10.1.0.4 DST=198.51.100.7 PROTO=TCP SPT=1 DPT=8080 UID=1001`

func TestParseKernelLog(t *testing.T) {
	d := ParseKernelLog(dmesg)
	if len(d) != 3 {
		t.Fatalf("want 3 drops, got %+v", d)
	}
	if d[0].IP != "1.1.1.1" || d[0].Port != 443 || d[0].Proto != "tcp" || d[0].UID != "1001" || d[0].Audit {
		t.Fatalf("first drop: %+v", d[0])
	}
	if !d[2].Audit || d[2].Port != 8080 {
		t.Fatalf("audit drop: %+v", d[2])
	}
}

func TestRecords(t *testing.T) {
	dns := []dnslog.Entry{
		{Time: time.Unix(0, 0), Name: "attacker.example", Rcode: "NXDOMAIN", Denied: true},
		{Name: "api.github.com", IPs: []string{"140.82.112.6"}},
		{Name: "attacker.example", Rcode: "NXDOMAIN", Denied: true}, // repeated lookup: one record
	}
	recs := Records(ModeBlock, dns, ParseKernelLog(dmesg))
	var got []string
	for _, r := range recs {
		if r.RuleID != RuleID || r.Verdict != "block" || r.Source != "network" || r.Tool != "network" {
			t.Fatalf("bad record: %+v", r)
		}
		got = append(got, r.Args[0])
	}
	// Audit-mode line is ignored in block mode.
	if strings.Join(got, ",") != "1.1.1.1:443,203.0.113.9:53,attacker.example" {
		t.Fatalf("records: %v", got)
	}
	aud := Records(ModeAudit, dns, ParseKernelLog(dmesg))
	if len(aud) != 2 || aud[0].Verdict != "would-block" {
		t.Fatalf("audit records: %+v", aud)
	}
}

func join(cmds [][]string) string {
	var b strings.Builder
	for _, c := range cmds {
		b.WriteString(strings.Join(c, " "))
		b.WriteString("\n")
	}
	return b.String()
}

func TestAllowIPWaitsForTheRuleAndRetriesFailures(t *testing.T) {
	release := make(chan struct{})
	var calls int32
	var mu sync.Mutex
	fail := true
	fw := &Firewall{Mode: ModeBlock, Run: func(argv []string) error {
		atomic.AddInt32(&calls, 1)
		<-release
		mu.Lock()
		defer mu.Unlock()
		if fail {
			fail = false
			return errors.New("xtables lock")
		}
		return nil
	}}
	// Two parallel lookups of the same address: neither may return before an
	// iptables call has finished, and the failed first call must be retried.
	var wg sync.WaitGroup
	returned := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); returned <- fw.AllowIP("140.82.112.21") }()
	}
	select {
	case <-returned:
		t.Fatal("AllowIP returned before the rule was added")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	wg.Wait()
	close(returned)
	var errs, oks int
	for err := range returned {
		if err != nil {
			errs++
		} else {
			oks++
		}
	}
	if oks < 1 || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("want the failed add retried and a success: oks=%d errs=%d calls=%d", oks, errs, calls)
	}
	// Once added, later lookups don't run iptables again.
	if err := fw.AllowIP("140.82.112.21"); err != nil || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("cached allow: err=%v calls=%d", err, calls)
	}
}

func TestHostsFileIPs(t *testing.T) {
	hosts := `127.0.0.1 localhost
::1 localhost ip6-localhost
10.1.0.4 fv-az123.internal  # runner itself
140.82.112.3 github.com
20.60.1.1 productionresultssa0.blob.core.windows.net
6.6.6.6 evil.test
`
	got := strings.Join(HostsFileIPs(hosts, DefaultAllowed), ",")
	if got != "140.82.112.3,20.60.1.1" {
		t.Fatalf("got %q", got)
	}
}

func TestStripNSSResolve(t *testing.T) {
	cases := map[string]string{
		"hosts:          files mdns4_minimal [NOTFOUND=return] resolve [!UNAVAIL=return] dns myhostname": "hosts: files mdns4_minimal [NOTFOUND=return] dns myhostname",
		"hosts: files resolve [!UNAVAIL=return] myhostname":                                              "hosts: files myhostname dns",
		"hosts: files dns": "hosts: files dns",
	}
	for in, want := range cases {
		conf := "passwd: files\n" + in + "\nnetworks: files\n"
		out, changed := StripNSSResolve(conf)
		if changed != (in != want) {
			t.Errorf("%q: changed=%v", in, changed)
		}
		if !strings.Contains(out, want+"\n") || !strings.HasPrefix(out, "passwd: files\n") {
			t.Errorf("%q:\n got %q\nwant line %q", in, out, want)
		}
	}
}

func TestSearchEchoesAreNotReportedTwice(t *testing.T) {
	sd := SearchDomains("nameserver 127.0.0.53\nsearch jt1qx.xx.internal.cloudapp.net\n", "runnervm1")
	dns := []dnslog.Entry{
		{Name: "hosted-compute-watchdog-prod-iad-01.githubapp.com", Denied: true},
		{Name: "hosted-compute-watchdog-prod-iad-01.githubapp.com.jt1qx.xx.internal.cloudapp.net", Denied: true},
		{Name: "statsig.anthropic.com"},
		{Name: "statsig.anthropic.com.jt1qx.xx.internal.cloudapp.net", Denied: true},
		{Name: "evil.example", Denied: true},
		{Name: "secret.internal.cloudapp.net", Denied: true}, // not an echo of anything queried
	}
	var got []string
	for _, e := range DropSearchEchoes(dns, sd) {
		if e.Denied {
			got = append(got, e.Name)
		}
	}
	want := "hosted-compute-watchdog-prod-iad-01.githubapp.com,evil.example,secret.internal.cloudapp.net"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
}

func TestGitHubRunnerInfraIsAllowed(t *testing.T) {
	for _, h := range []string{"hosted-compute-watchdog-prod-iad-01.githubapp.com", "hosted-compute-request-orchestrator-prod-iad-01.githubapp.com", "statsig.anthropic.com", "downloads.claude.ai"} {
		if !Allowed(h, DefaultAllowed) {
			t.Errorf("%s should be allowed by default", h)
		}
	}
}
