package jobctx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func ctxFor(t *testing.T, event, payload, workflow string) Context {
	t.Helper()
	dir := t.TempDir()
	ev := filepath.Join(dir, "event.json")
	_ = os.WriteFile(ev, []byte(payload), 0o644)
	if workflow != "" {
		_ = os.MkdirAll(filepath.Join(dir, ".github/workflows"), 0o755)
		_ = os.WriteFile(filepath.Join(dir, ".github/workflows/w.yml"), []byte(workflow), 0o644)
	}
	for k, v := range map[string]string{
		"GITHUB_EVENT_NAME": event, "GITHUB_EVENT_PATH": ev, "GITHUB_REPOSITORY": "acme/api",
		"GITHUB_RUN_ID": "1", "GITHUB_JOB": "triage", "GITHUB_WORKSPACE": dir,
		"GITHUB_WORKFLOW_REF": "acme/api/.github/workflows/w.yml@refs/heads/main",
		"GITHUB_SERVER_URL":   "https://github.com", "TITRA_APPROVED_BY": "", "TITRA_APPROVE_LABEL": "",
	} {
		t.Setenv(k, v)
	}
	return FromEnv()
}

func TestOutsiderIssueIsUntrusted(t *testing.T) {
	c := ctxFor(t, "issues", `{"action":"opened","issue":{"number":7,"title":"x","author_association":"NONE","user":{"login":"eve"}},"sender":{"login":"eve"}}`, "")
	if c.Trusted || c.Actor != "eve" || c.Number != "7" || len(c.Untrusted) == 0 {
		t.Fatalf("outsider issue: %+v", c)
	}
}

func TestMemberIsTrusted(t *testing.T) {
	c := ctxFor(t, "issue_comment", `{"action":"created","issue":{"number":3,"title":"x"},"comment":{"author_association":"MEMBER"},"sender":{"login":"mo"}}`, "")
	if !c.Trusted {
		t.Fatalf("member comment should be trusted: %+v", c)
	}
}

func TestForkPRIsUntrustedAndFlagged(t *testing.T) {
	c := ctxFor(t, "pull_request_target", `{"pull_request":{"number":9,"title":"x","author_association":"CONTRIBUTOR","head":{"repo":{"full_name":"eve/api"}}},"sender":{"login":"eve"}}`, "")
	if c.Trusted || c.Number != "9" {
		t.Fatalf("fork PR: %+v", c)
	}
	found := false
	for _, u := range c.Untrusted {
		if u == "fork: eve/api" {
			found = true
		}
	}
	if !found {
		t.Fatalf("fork should be listed as untrusted input: %v", c.Untrusted)
	}
}

func TestPushAndScheduleAreTrusted(t *testing.T) {
	for _, ev := range []string{"push", "schedule", "workflow_dispatch"} {
		if c := ctxFor(t, ev, `{"sender":{"login":"mo"}}`, ""); !c.Trusted {
			t.Fatalf("%s should be trusted", ev)
		}
	}
}

func TestWorkflowRunIsNotTrusted(t *testing.T) {
	if c := ctxFor(t, "workflow_run", `{"sender":{"login":"mo"}}`, ""); c.Trusted {
		t.Fatal("workflow_run can follow untrusted code")
	}
}

func TestLabeledRunKeepsAuthorAsActor(t *testing.T) {
	// The maintainer adds the approval label; the input the agent reads is
	// still the outsider's, so the outsider stays the actor and stays untrusted.
	c := ctxFor(t, "issues", `{"action":"labeled","label":{"name":"titra:approve"},"issue":{"number":7,"title":"x","author_association":"NONE","user":{"login":"eve"}},"sender":{"login":"maintainer"}}`, "")
	if c.Actor != "eve" || c.Trusted {
		t.Fatalf("labeled run: actor %q trusted %v", c.Actor, c.Trusted)
	}
}

func TestApprovalFromEnv(t *testing.T) {
	c := ctxFor(t, "issues", `{"action":"opened","issue":{"number":1,"title":"x","author_association":"NONE","user":{"login":"eve"}},"sender":{"login":"eve"}}`, "")
	if c.ApprovedBy != "" {
		t.Fatal("no approval expected")
	}
	t.Setenv("TITRA_APPROVED_BY", "mo")
	if FromEnv().ApprovedBy != "mo" {
		t.Fatal("approval should come from TITRA_APPROVED_BY")
	}
}

func TestWorkflowPermissionsAndAgents(t *testing.T) {
	wf := "on: issues\npermissions:\n  contents: read\njobs:\n  triage:\n    permissions:\n      contents: write\n      issues: write\n    steps:\n      - uses: actions/checkout@v4\n      - uses: anthropics/claude-code-base-action@beta\n"
	c := ctxFor(t, "issues", `{"action":"opened","issue":{"number":1,"title":"x","author_association":"NONE","user":{"login":"eve"}}}`, wf)
	if got := c.WriteAccess(); len(got) != 2 || got[0] != "contents" || got[1] != "issues" {
		t.Fatalf("job-level permissions should win: %v (%s)", got, c.PermNote)
	}
	if len(c.Agents) != 1 || c.Agents[0] != "Claude Code (anthropics/claude-code-base-action@beta)" {
		t.Fatalf("agents: %v", c.Agents)
	}
}

func TestMissingEventFileDoesNotPanic(t *testing.T) {
	t.Setenv("GITHUB_EVENT_PATH", "/nonexistent/event.json")
	t.Setenv("GITHUB_EVENT_NAME", "issues")
	_ = FromEnv()
}

// The real demo workflow: block scalars everywhere, permissions at job level.
// The small YAML parser can't read it; permissions must still be found.
const realWorkflow = `name: Issue Triage
on:
  issues:
    types: [opened, labeled]   # "labeled" lets a maintainer approve a re-run

jobs:
  triage:
    if: github.event.action == 'opened' || github.event.label.name == 'titra:approve'
    runs-on: ubuntu-latest
    timeout-minutes: 10
    permissions:
      contents: read
      issues: write          # (D) token in scope
    steps:
      - uses: actions/checkout@v6
      - name: Build prompt
        uses: actions/github-script@v7
        with:
          script: |
            const prompt = [
              'permissions:',
              'contents: write',
            ].join('\n');
      - name: Run Claude
        uses: anthropics/claude-code-base-action@beta
`

func TestPermissionsFromRealWorkflow(t *testing.T) {
	c := ctxFor(t, "issues", `{"action":"opened","issue":{"number":7,"title":"x","author_association":"NONE","user":{"login":"eve"}}}`, realWorkflow)
	if got := c.WriteAccess(); len(got) != 1 || got[0] != "issues" {
		t.Fatalf("want write: issues (from the job, not the script text), got %v %q", got, c.PermNote)
	}
	if c.PermNote != "declared in job" {
		t.Fatalf("note: %q", c.PermNote)
	}
	if len(c.Agents) != 1 {
		t.Fatalf("agent still detected: %v", c.Agents)
	}
}

func TestScanPermissionsForms(t *testing.T) {
	cases := []struct {
		src, job, want, from string
	}{
		{"permissions: write-all\njobs:\n  a:\n    steps:\n      - run: |\n          x\n", "a", "all=write", "workflow"},
		{"permissions:\n  contents: read\njobs:\n  a:\n    permissions: { contents: write, pull-requests: write }\n", "a", "contents=write,pull-requests=write", "job"},
		{"jobs:\n  other:\n    permissions:\n      contents: write\n  a:\n    steps: []\n", "a", "", ""},
		{"permissions: {}\njobs:\n  a:\n    steps: []\n", "a", "", "workflow"},
		{"'permissions':\n  \"issues\": 'write'\njobs: {}\n", "a", "issues=write", "workflow"},
	}
	for i, c := range cases {
		m, from, _ := scanPermissions(c.src, c.job)
		var parts []string
		for _, k := range []string{"all", "contents", "issues", "pull-requests"} {
			if v, ok := m[k]; ok {
				parts = append(parts, k+"="+v)
			}
		}
		if got := strings.Join(parts, ","); got != c.want || from != c.from {
			t.Errorf("case %d: got %q from %q, want %q from %q", i, got, from, c.want, c.from)
		}
	}
}
