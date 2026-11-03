// Package report renders the JSONL action log into something a human reads: a
// terminal summary for local runs, and a Markdown block for a GitHub Actions job
// summary. It is the readable face of the "see" half of Titra.
package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/ChelateSec/titra/internal/audit"
)

// Summary is the rolled-up view of a log.
type Summary struct {
	Total      int
	Allowed    int
	Blocked    int
	WouldBlock int
	Records    []audit.Record
}

// Summarize counts verdicts across all records.
func Summarize(recs []audit.Record) Summary {
	s := Summary{Total: len(recs), Records: recs}
	for _, r := range recs {
		switch r.Verdict {
		case "block":
			s.Blocked++
		case "would-block":
			s.WouldBlock++
		default:
			s.Allowed++
		}
	}
	return s
}

// HasFindings reports whether anything was blocked or would have been.
func (s Summary) HasFindings() bool { return s.Blocked > 0 || s.WouldBlock > 0 }

// Terminal writes a compact, colorless summary suitable for a CI or local log.
func Terminal(w io.Writer, s Summary) {
	fmt.Fprintf(w, "titra: %d action(s) — %d allowed, %d blocked, %d would-block\n",
		s.Total, s.Allowed, s.Blocked, s.WouldBlock)
	// Only the interesting lines (blocked / would-block), newest first.
	findings := interesting(s.Records)
	if len(findings) == 0 {
		if s.Total > 0 {
			fmt.Fprintln(w, "       no risky actions observed.")
		}
		return
	}
	for _, r := range findings {
		mark := "WOULD-BLOCK"
		if r.Verdict == "block" {
			mark = "BLOCKED"
		}
		fmt.Fprintf(w, "       %-11s %-8s %s  [%s/%s]\n",
			mark, r.Tool, cmd(r), r.RuleID, r.Severity)
	}
}

// Markdown renders a GitHub-flavored summary block for $GITHUB_STEP_SUMMARY.
func Markdown(w io.Writer, s Summary) {
	fmt.Fprintln(w, "## 🛡️ Titra — agent action report")
	fmt.Fprintln(w)
	verdict := "✅ No risky actions observed."
	if s.Blocked > 0 {
		verdict = fmt.Sprintf("⛔ **%d action(s) blocked.**", s.Blocked)
	} else if s.WouldBlock > 0 {
		verdict = fmt.Sprintf("⚠️ **%d action(s) would be blocked** (monitor/dry-run mode).", s.WouldBlock)
	}
	fmt.Fprintln(w, verdict)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%d action(s) observed — %d allowed, %d blocked, %d would-block.\n\n",
		s.Total, s.Allowed, s.Blocked, s.WouldBlock)

	findings := interesting(s.Records)
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w, "| Verdict | Tool | Command | Rule | Severity |")
	fmt.Fprintln(w, "| --- | --- | --- | --- | --- |")
	for _, r := range findings {
		mark := "⚠️ would-block"
		if r.Verdict == "block" {
			mark = "⛔ blocked"
		}
		fmt.Fprintf(w, "| %s | `%s` | `%s` | %s | %s |\n",
			mark, r.Tool, mdEscape(cmd(r)), r.RuleID, r.Severity)
	}
}

// interesting returns the blocked / would-block records, most severe first.
func interesting(recs []audit.Record) []audit.Record {
	var out []audit.Record
	for _, r := range recs {
		if r.Verdict == "block" || r.Verdict == "would-block" {
			out = append(out, r)
		}
	}
	rank := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
	sort.SliceStable(out, func(i, j int) bool {
		return rank[out[i].Severity] > rank[out[j].Severity]
	})
	return out
}

func cmd(r audit.Record) string {
	return strings.TrimSpace(r.Tool + " " + strings.Join(r.Args, " "))
}

func mdEscape(s string) string {
	return strings.ReplaceAll(s, "|", "\\|")
}

// Load reads a log file and summarizes it in one step.
func Load(path string) (Summary, error) {
	recs, err := audit.ReadAll(path)
	if err != nil {
		return Summary{}, err
	}
	return Summarize(recs), nil
}
