// Package hook plugs Titra into the agent itself. Claude Code calls a hook
// before every tool use; Titra logs the call and, in enforce mode, refuses it
// (exit code 2) when it breaks policy. This is the agent's intent, recorded at
// the source: what it was about to run, read, or fetch, before anything ran.
package hook

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/engine"
	"github.com/ChelateSec/titra/internal/guard"
	"github.com/ChelateSec/titra/internal/policy"
	"github.com/ChelateSec/titra/internal/reporter"
)

// input is the JSON Claude Code sends on stdin.
type input struct {
	HookEvent string         `json:"hook_event_name"`
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
	Cwd       string         `json:"cwd"`
}

// Claude handles one Claude Code PreToolUse call and returns the exit code.
// 0 lets the tool run; 2 blocks it and shows stderr to the agent.
func Claude(stdin io.Reader, stderr io.Writer) int {
	raw, err := io.ReadAll(stdin)
	if err != nil {
		return 0
	}
	var in input
	if json.Unmarshal(raw, &in) != nil || in.ToolName == "" {
		return 0
	}

	cfg := guard.ConfigFromEnv()
	pol, err := guard.LoadPolicy(cfg)
	if pol == nil {
		fmt.Fprintf(stderr, "titra: internal policy error: %v (allowing)\n", err)
		return 0
	}
	if err != nil {
		fmt.Fprintf(stderr, "titra: policy error: %v — using Titra's built-in rules instead\n", err)
	}
	eng, err := engine.New(pol)
	if err != nil {
		return 0
	}

	var logger *audit.Logger
	if cfg.LogPath != "" {
		logger, _ = audit.Open(cfg.LogPath)
	}

	code := 0
	refuse := func(a engine.Attempt, d engine.Decision) {
		rec := audit.NewRecord(a, d)
		rec.Source = "claude-code"
		rec.AgentTool = in.ToolName
		if logger != nil {
			_ = logger.Append(rec)
		}
		reporter.Report(rec)
		if d.Blocked() && code == 0 {
			code = 2
			fmt.Fprintf(stderr, "titra blocked this %s call: %s [%s/%s]. %s. Do not retry it or work around it.\n",
				in.ToolName, strings.TrimSpace(a.Tool+" "+a.ArgString()), d.RuleID, d.Severity, d.Reason)
		}
	}

	// Write guard: the agent may only write inside the repository checkout.
	if sc := scopeFromEnv(in.Cwd); sc != nil && pol.Writes != "any" {
		for _, target := range writeTargetsFor(in.ToolName, in.ToolInput) {
			if ok, why := sc.check(target); !ok {
				refuse(engine.Attempt{Tool: "write", Args: []string{target}},
					eng.Decide(RuleWrite, policy.SevHigh, "Agent may not write here: "+why))
			}
		}
	}

	for _, a := range Attempts(in.ToolName, in.ToolInput) {
		d := eng.Evaluate(a)
		rec := audit.NewRecord(a, d)
		rec.Source = "claude-code"
		rec.AgentTool = in.ToolName
		if logger != nil {
			_ = logger.Append(rec)
		}
		reporter.Report(rec)
		if d.Blocked() && code == 0 {
			code = 2
			fmt.Fprintf(stderr, "titra blocked this %s call: %s [%s/%s]. %s. Do not retry it or work around it.\n",
				in.ToolName, strings.TrimSpace(a.Tool+" "+a.ArgString()), d.RuleID, d.Severity, d.Reason)
		}
	}
	return code
}

// writeTargetsFor lists the files an agent tool call would write.
func writeTargetsFor(tool string, in map[string]any) []string {
	s := func(k string) string { v, _ := in[k].(string); return v }
	switch tool {
	case "Bash":
		return WriteTargets(s("command"))
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		if p := first(s("file_path"), s("notebook_path")); p != "" {
			return []string{p}
		}
	}
	return nil
}

// Attempts turns one agent tool call into the actions it would take.
func Attempts(tool string, in map[string]any) []engine.Attempt {
	s := func(k string) string { v, _ := in[k].(string); return v }
	switch tool {
	case "Bash":
		return Commands(s("command"))
	case "Read", "NotebookRead":
		return []engine.Attempt{{Tool: "read", Args: []string{first(s("file_path"), s("notebook_path"))}}}
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return []engine.Attempt{{Tool: "write", Args: []string{first(s("file_path"), s("notebook_path"))}}}
	case "WebFetch":
		return []engine.Attempt{{Tool: "webfetch", Args: []string{s("url")}}}
	case "WebSearch":
		return []engine.Attempt{{Tool: "websearch", Args: []string{s("query")}}}
	case "Grep", "Glob":
		return []engine.Attempt{{Tool: strings.ToLower(tool), Args: nonEmpty(s("pattern"), s("path"))}}
	}
	b, _ := json.Marshal(in)
	return []engine.Attempt{{Tool: tool, Args: []string{string(b)}}}
}

// Commands splits a shell command line into the individual commands it runs,
// so `cd x && git push` is judged as `cd x` and `git push`. It follows
// `bash -c "..."`, `sh -c`, `eval` and `sudo` into the inner command.
func Commands(line string) []engine.Attempt {
	var out []engine.Attempt
	for _, seg := range splitSegments(line) {
		words := shellWords(seg)
		// skip leading VAR=value assignments
		for len(words) > 0 && strings.Contains(words[0], "=") && !strings.HasPrefix(words[0], "-") {
			words = words[1:]
		}
		for len(words) > 0 && (words[0] == "sudo" || words[0] == "env" || words[0] == "exec" || words[0] == "nohup" || words[0] == "time") {
			words = words[1:]
			for len(words) > 0 && (strings.HasPrefix(words[0], "-") || strings.Contains(words[0], "=")) {
				words = words[1:]
			}
		}
		if len(words) == 0 {
			continue
		}
		name := filepath.Base(words[0])
		if (name == "bash" || name == "sh" || name == "zsh" || name == "dash") && len(words) >= 3 && words[1] == "-c" {
			out = append(out, Commands(words[2])...)
			continue
		}
		if name == "eval" && len(words) >= 2 {
			out = append(out, Commands(strings.Join(words[1:], " "))...)
			continue
		}
		out = append(out, engine.Attempt{Tool: name, Args: words[1:]})
	}
	return out
}

// splitSegments cuts on ; && || | & and newlines outside quotes, and pulls
// $( ... ) and backtick substitutions out as their own segments.
func splitSegments(s string) []string {
	var segs []string
	var cur strings.Builder
	inS, inD := false, false
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			segs = append(segs, t)
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && !inS && i+1 < len(s):
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case c == '\'' && !inD:
			inS = !inS
			cur.WriteByte(c)
		case c == '"' && !inS:
			inD = !inD
			cur.WriteByte(c)
		case !inS && c == '$' && i+1 < len(s) && s[i+1] == '(':
			depth, j := 1, i+2
			for ; j < len(s) && depth > 0; j++ {
				if s[j] == '(' {
					depth++
				} else if s[j] == ')' {
					depth--
				}
			}
			segs = append(segs, splitSegments(s[i+2:j-1])...)
			cur.WriteString("SUBST")
			i = j - 1
		case !inS && c == '`':
			j := strings.IndexByte(s[i+1:], '`')
			if j < 0 {
				cur.WriteByte(c)
				continue
			}
			segs = append(segs, splitSegments(s[i+1:i+1+j])...)
			cur.WriteString("SUBST")
			i += j + 1
		case c == '&' && ((i > 0 && (s[i-1] == '>' || s[i-1] == '<')) || (i+1 < len(s) && s[i+1] == '>')):
			cur.WriteByte(c) // redirection like 2>&1 or &>file, not a separator
		case !inS && !inD && (c == ';' || c == '\n' || c == '|' || c == '&' || c == '(' || c == ')'):
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return segs
}

// shellWords splits on whitespace, honouring quotes and backslashes.
func shellWords(s string) []string {
	var words []string
	var cur strings.Builder
	inS, inD, have := false, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && !inS && i+1 < len(s):
			cur.WriteByte(s[i+1])
			i++
			have = true
		case c == '\'' && !inD:
			inS = !inS
			have = true
		case c == '"' && !inS:
			inD = !inD
			have = true
		case (c == ' ' || c == '\t') && !inS && !inD:
			if have {
				words = append(words, cur.String())
				cur.Reset()
				have = false
			}
		default:
			cur.WriteByte(c)
			have = true
		}
	}
	if have {
		words = append(words, cur.String())
	}
	return words
}

func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func nonEmpty(v ...string) []string {
	var out []string
	for _, s := range v {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// Main is the entry point for `titra hook claude`.
func Main(args []string) {
	if len(args) == 0 || args[0] != "claude" {
		fmt.Fprintln(os.Stderr, "usage: titra hook claude   (reads a Claude Code hook event on stdin)")
		os.Exit(2)
	}
	os.Exit(Claude(os.Stdin, os.Stderr))
}
