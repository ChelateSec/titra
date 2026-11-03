package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/jobctx"
)

// StoryJSON writes the story as indented JSON (for the uploaded artifact and
// the org roll-up).
func StoryJSON(w io.Writer, s Story) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}

// StoryMarkdown renders the run report for $GITHUB_STEP_SUMMARY. It reads as a
// short story: who triggered the run, which agent ran with what access, what it
// tried, and what else the job touched.
func StoryMarkdown(w io.Writer, s Story) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }

	switch s.Status {
	case "blocked":
		p("## ⛔ Titra blocked %d action(s)\n\n", len(s.Blocked))
	case "warning":
		p("## ⚠️ Titra — %d thing(s) to review\n\n", s.Warnings())
	default:
		p("## ✅ Titra — nothing risky\n\n")
	}

	// The story line.
	c := s.Context
	if line := storyLine(s); line != "" {
		p("%s\n\n", line)
	}

	// Context table.
	p("| | |\n| --- | --- |\n")
	if c.Repo != "" {
		p("| **Repo** | `%s` |\n", c.Repo)
	}
	if c.Workflow != "" {
		wf := c.Workflow
		if c.WorkflowFile != "" {
			wf = fmt.Sprintf("%s (`%s`)", c.Workflow, c.WorkflowFile)
		}
		p("| **Workflow** | %s |\n", wf)
	}
	if c.Event != "" {
		p("| **Trigger** | `%s`%s |\n", c.Event, triggeredBy(c))
	}
	if c.Subject != "" {
		p("| **Input** | %s |\n", mdEscape(c.Subject))
	}
	p("| **Who** | %s |\n", trustCell(c))
	if len(c.Agents) > 0 {
		p("| **Agent** | %s |\n", mdEscape(strings.Join(c.Agents, ", ")))
	}
	if perm := permCell(c); perm != "" {
		p("| **Token** | %s |\n", perm)
	}
	p("| **Mode** | `%s` |\n", orDash(s.Mode))
	if c.ApprovedBy != "" {
		p("| **Approved** | by `%s` with the `%s` label — this run was watched, not blocked |\n", c.ApprovedBy, orDash(c.ApproveLabel))
	}
	p("\n")

	// Blocked / would-block table.
	if len(s.Blocked) > 0 || len(s.WouldBlock) > 0 {
		p("### Actions\n\n")
		p("| Verdict | Source | Command | Rule | Severity |\n| --- | --- | --- | --- | --- |\n")
		for _, r := range s.Blocked {
			p("| ⛔ blocked | %s | `%s` | %s | %s |\n", srcCell(r), mdEscape(cmd(r)), r.RuleID, r.Severity)
		}
		for _, r := range s.WouldBlock {
			p("| ⚠️ would block | %s | `%s` | %s | %s |\n", srcCell(r), mdEscape(cmd(r)), r.RuleID, r.Severity)
		}
		p("\n")
	}

	// How a maintainer allows a blocked run.
	if len(s.Blocked) > 0 && c.ApprovedBy == "" && c.Number != "" && c.ApproveLabel != "" {
		p("> **Is this expected?** A maintainer can review the blocked actions above and add the `%s` label to #%s. ", c.ApproveLabel, c.Number)
		p("The workflow runs once more with Titra watching instead of blocking, and the approval is recorded. Outside contributors can't add labels, so they can't approve themselves.\n\n")
	}

	// What else the job touched (tracing only).
	if s.Traced {
		p("### Everything else the job did\n\n")
		p("Titra watched the whole job — %d process(es) — not only the guarded commands.\n\n", s.Processes)

		if un := s.Unexpected(); len(un) > 0 {
			p("**Unexpected network destinations**\n\n")
			p("| Destination | Port | Reached by |\n| --- | --- | --- |\n")
			for _, d := range un {
				p("| %s | %d | `%s` |\n", destName(d), d.Port, strings.Join(d.Procs, "`, `"))
			}
			p("\n")
		}
		if len(s.CredReads) > 0 {
			p("**Credential files read by something unexpected**\n\n")
			for _, f := range s.CredReads {
				p("- `%s` read by `%s`\n", f.Path, f.Proc)
			}
			p("\n")
		}
		if len(s.Bypasses) > 0 {
			p("**Guarded tools run directly (around the shims)**\n\n")
			for _, b := range s.Bypasses {
				p("- `%s` — `%s`\n", b.Tool, mdEscape(b.Cmd))
			}
			p("\n")
		}
		if len(s.Unexpected()) == 0 && len(s.CredReads) == 0 && len(s.Bypasses) == 0 {
			p("Nothing out of the ordinary: no unexpected destinations, no stray credential reads, no tools run around the guard.\n\n")
		}
	} else if s.TraceNote != "" {
		p("_%s._\n\n", s.TraceNote)
	}

	p("---\n")
	p("<sub>Titra · Chelate Sec · securing the agentic CI/CD. Blocking is deterministic policy, never a model.</sub>\n")
}

// storyLine is the one-sentence narrative at the top.
func storyLine(s Story) string {
	c := s.Context
	who := "someone"
	if c.Actor != "" {
		who = "`" + c.Actor + "`"
	}
	if !c.Trusted && c.Association != "" && c.Association != "OWNER" && c.Association != "MEMBER" && c.Association != "COLLABORATOR" {
		who += " (outside contributor)"
	}
	agent := "an agent"
	if len(c.Agents) == 1 {
		agent = strings.SplitN(c.Agents[0], " (", 2)[0]
	}

	var b strings.Builder
	if c.Subject != "" {
		fmt.Fprintf(&b, "%s opened %s. ", who, mdEscape(trimSubject(c.Subject)))
	} else if c.Event != "" {
		fmt.Fprintf(&b, "Triggered by `%s` (%s). ", c.Event, who)
	}

	access := ""
	if wa := c.WriteAccess(); len(wa) > 0 {
		access = fmt.Sprintf(" with **%s** write access", strings.Join(wa, ", "))
	}
	fmt.Fprintf(&b, "%s ran%s", agent, access)

	switch s.Status {
	case "blocked":
		fmt.Fprintf(&b, " and tried %d dangerous action(s) — Titra stopped %s before %s ran.",
			len(s.Blocked), plural(len(s.Blocked), "it", "them"), plural(len(s.Blocked), "it", "they"))
	case "warning":
		b.WriteString(". Titra flagged a few things worth a look.")
	default:
		b.WriteString(". Nothing risky happened.")
	}
	return strings.TrimSpace(b.String())
}

func trustCell(c jobctx.Context) string {
	if c.Actor == "" && c.Association == "" {
		return "—"
	}
	who := "`" + orDash(c.Actor) + "`"
	if c.Trusted {
		return fmt.Sprintf("%s ✓ %s", who, c.TrustNote)
	}
	note := c.TrustNote
	if note == "" {
		note = "trust unknown"
	}
	return fmt.Sprintf("%s ⚠️ %s", who, note)
}

func permCell(c jobctx.Context) string {
	if c.PermNote == "" && len(c.Permissions) == 0 {
		return ""
	}
	wa := c.WriteAccess()
	if len(wa) > 0 {
		return fmt.Sprintf("write: **%s** <sub>(%s)</sub>", strings.Join(wa, ", "), c.PermNote)
	}
	if len(c.Permissions) > 0 {
		return fmt.Sprintf("read-only <sub>(%s)</sub>", c.PermNote)
	}
	return c.PermNote
}

func triggeredBy(c jobctx.Context) string {
	if c.Actor == "" {
		return ""
	}
	return " by `" + c.Actor + "`"
}

func srcCell(r audit.Record) string {
	switch r.Source {
	case "claude-code":
		t := r.AgentTool
		if t == "" {
			t = "Claude Code"
		}
		return "agent (`" + t + "`)"
	case "network":
		return "network"
	default:
		return "shim"
	}
}

func destName(d Dest) string {
	if d.Host != "" {
		return fmt.Sprintf("`%s` <sub>%s</sub>", d.Host, d.IP)
	}
	return "`" + d.IP + "`"
}

func trimSubject(s string) string {
	// "issue #42: Fix the thing" -> "issue #42"
	if i := strings.Index(s, ": "); i >= 0 {
		return s[:i]
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// StoryTerminal renders a compact version for a local or CI log.
func StoryTerminal(w io.Writer, s Story) {
	p := func(f string, a ...any) { fmt.Fprintf(w, f, a...) }
	switch s.Status {
	case "blocked":
		p("titra: ⛔ blocked %d action(s)\n", len(s.Blocked))
	case "warning":
		p("titra: ⚠️ %d thing(s) to review\n", s.Warnings())
	default:
		p("titra: ✅ nothing risky\n")
	}
	if line := storyLine(s); line != "" {
		p("  %s\n", stripMD(line))
	}
	for _, r := range s.Blocked {
		p("  BLOCKED      %-6s %s  [%s/%s]\n", shortSrc(r), cmd(r), r.RuleID, r.Severity)
	}
	for _, r := range s.WouldBlock {
		p("  WOULD-BLOCK  %-6s %s  [%s/%s]\n", shortSrc(r), cmd(r), r.RuleID, r.Severity)
	}
	if s.Traced {
		for _, d := range s.Unexpected() {
			p("  EGRESS       %s:%d  by %s\n", orDash(d.Host), d.Port, strings.Join(d.Procs, ","))
		}
		for _, f := range s.CredReads {
			p("  CRED-READ    %s  by %s\n", f.Path, f.Proc)
		}
		for _, b := range s.Bypasses {
			p("  BYPASS       %s\n", b.Cmd)
		}
	}
}

func shortSrc(r audit.Record) string {
	switch r.Source {
	case "claude-code":
		return "agent"
	case "network":
		return "network"
	}
	return "shim"
}

func stripMD(s string) string {
	r := strings.NewReplacer("**", "", "`", "")
	return r.Replace(s)
}
