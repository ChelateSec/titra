package hook

// The write guard keeps an agent's writes inside the repository checkout.
//
// Outside it are the places a hijacked agent writes to escalate or persist:
// $GITHUB_ENV / $GITHUB_PATH (inject environment or binaries into every later
// step), shell profiles, other actions' code and the tool cache (run by later
// steps), Titra's own files, and the agent's own settings (to drop the hook).
// Inside the checkout, .git/ (hooks run by later git commands) and the
// workflow and action definitions are off limits too.

import (
	"os"
	"path/filepath"
	"strings"
)

// RuleWrite is the rule ID for writes the guard refuses.
const RuleWrite = "write-outside-workspace"

// scratchRoot is where agents may write scratch files outside the checkout.
// A variable so tests (whose temp dirs live under /tmp) can move it.
var scratchRoot = "/tmp"

// writeScope describes where the agent may write.
type writeScope struct {
	workspace string
	cwd       string
	env       func(string) string
}

// scopeFromEnv builds the scope for this job. With no workspace known (a local
// run outside CI) the guard is off.
func scopeFromEnv(cwd string) *writeScope {
	ws := firstEnv("TITRA_WORKSPACE", "GITHUB_WORKSPACE")
	if ws == "" {
		return nil
	}
	if cwd == "" {
		cwd = ws
	}
	return &writeScope{workspace: realPath(ws), cwd: cwd, env: os.Getenv}
}

func firstEnv(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// commandFiles are the runner's per-step command files: writing to them
// changes the environment, PATH or outputs of every later step.
var commandFiles = []string{"GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STATE", "GITHUB_STEP_SUMMARY"}

// check reports whether a write to target is allowed, and why not.
func (sc *writeScope) check(target string) (bool, string) {
	raw := strings.TrimSpace(target)
	if raw == "" {
		return true, ""
	}
	for _, k := range commandFiles {
		if strings.Contains(raw, "$"+k) || strings.Contains(raw, "${"+k+"}") {
			return false, "writes to the runner's $" + k + " file, which changes every later step"
		}
	}
	p := sc.expand(raw)
	// "SUBST" is what the command splitter leaves where $(...) or `...` was.
	if strings.ContainsAny(p, "$`") || strings.Contains(p, "SUBST") {
		return false, "can't tell where this writes (" + raw + ")"
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(sc.cwd, p)
	}
	p = realPath(filepath.Clean(p))

	switch {
	case p == "/dev/null" || p == "/dev/stdout" || p == "/dev/stderr" || p == "/dev/tty" || strings.HasPrefix(p, "/dev/fd/"):
		return true, ""
	}
	for _, k := range commandFiles {
		if f := sc.env(k); f != "" && p == realPath(f) {
			return false, "writes to the runner's $" + k + " file, which changes every later step"
		}
	}
	if within(p, scratchRoot) && !within(p, filepath.Join(scratchRoot, "titra")) {
		return true, ""
	}
	if !within(p, sc.workspace) {
		return false, "outside the repository checkout (" + p + ")"
	}
	rel, _ := filepath.Rel(sc.workspace, p)
	rel = filepath.ToSlash(rel)
	switch {
	case rel == ".git" || strings.HasPrefix(rel, ".git/"):
		return false, "inside .git/ (hooks and config there run with later git commands)"
	case strings.HasPrefix(rel, ".github/workflows/") || rel == ".github/workflows",
		strings.HasPrefix(rel, ".github/actions/") || rel == ".github/actions":
		return false, "workflow and action definitions"
	}
	return true, ""
}

func (sc *writeScope) expand(p string) string {
	if p == "~" || strings.HasPrefix(p, "~/") {
		p = sc.env("HOME") + p[1:]
	}
	return os.Expand(p, func(k string) string {
		if v := sc.env(k); v != "" {
			return v
		}
		return "$" + k // leave unknown variables visible, so check() refuses them
	})
}

func within(p, root string) bool {
	if root == "" {
		return false
	}
	root = filepath.Clean(root)
	return p == root || strings.HasPrefix(p, root+string(filepath.Separator))
}

// realPath resolves symlinks in the longest existing prefix of p, so a link
// inside the workspace can't point a write somewhere else.
func realPath(p string) string {
	p = filepath.Clean(p)
	rest := ""
	cur := p
	for {
		if r, err := filepath.EvalSymlinks(cur); err == nil {
			if rest == "" {
				return r
			}
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return p
		}
		if rest == "" {
			rest = filepath.Base(cur)
		} else {
			rest = filepath.Join(filepath.Base(cur), rest)
		}
		cur = parent
	}
}

// WriteTargets lists the files a shell command line writes to: redirections
// (>, >>, &>, 2>), and the destinations of tee, cp, mv, install, ln, sed -i,
// dd of=, touch, mkdir, rm, chmod, chown, truncate. It follows bash -c / sh -c
// / eval into the inner command, like Commands does.
func WriteTargets(line string) []string {
	var out []string
	for _, seg := range splitSegments(line) {
		out = append(out, redirectTargets(seg)...)
		words := shellWords(seg)
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
		args := words[1:]
		if (name == "bash" || name == "sh" || name == "zsh" || name == "dash") && len(args) >= 2 && args[0] == "-c" {
			out = append(out, WriteTargets(args[1])...)
			continue
		}
		if name == "eval" {
			out = append(out, WriteTargets(strings.Join(args, " "))...)
			continue
		}
		out = append(out, commandWriteTargets(name, args)...)
	}
	return out
}

// redirectTargets finds output redirections outside quotes.
func redirectTargets(seg string) []string {
	var out []string
	inS, inD := false, false
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c == '\\' && !inS:
			i++
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case c == '>' && !inS && !inD:
			j := i + 1
			if j < len(seg) && (seg[j] == '>' || seg[j] == '|') {
				j++
			}
			if j < len(seg) && seg[j] == '&' { // >&2, >&- : duplicating a descriptor
				i = j
				continue
			}
			for j < len(seg) && (seg[j] == ' ' || seg[j] == '\t') {
				j++
			}
			tok, end := readToken(seg, j)
			if tok != "" {
				out = append(out, tok)
			}
			i = end - 1
		}
	}
	return out
}

// readToken reads one shell word starting at i, removing quotes.
func readToken(s string, i int) (string, int) {
	var b strings.Builder
	inS, inD := false, false
	for ; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && !inS && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '\'' && !inD:
			inS = !inS
		case c == '"' && !inS:
			inD = !inD
		case !inS && !inD && (c == ' ' || c == '\t' || c == ';' || c == '|' || c == '&' || c == '<' || c == '>' || c == ')'):
			return b.String(), i
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), i
}

func operands(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i+1:]...)
		}
		if strings.HasPrefix(a, "-") && a != "-" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func commandWriteTargets(name string, args []string) []string {
	ops := operands(args)
	switch name {
	case "tee", "touch", "mkdir", "rm", "rmdir", "truncate", "shred", "unlink":
		return ops
	case "cp", "mv", "install", "ln", "rsync", "scp":
		for i, a := range args {
			if (a == "-t" || a == "--target-directory") && i+1 < len(args) {
				return []string{args[i+1]}
			}
			if strings.HasPrefix(a, "--target-directory=") {
				return []string{strings.TrimPrefix(a, "--target-directory=")}
			}
		}
		if len(ops) >= 2 {
			return ops[len(ops)-1:]
		}
	case "chmod", "chown", "chgrp":
		if len(ops) >= 2 {
			return ops[1:]
		}
	case "sed", "perl":
		inPlace := false
		for _, a := range args {
			if a == "-i" || strings.HasPrefix(a, "-i") || strings.HasPrefix(a, "--in-place") || (name == "perl" && strings.Contains(a, "i") && strings.HasPrefix(a, "-") && strings.Contains(a, "p")) {
				inPlace = true
			}
		}
		if inPlace && len(ops) >= 2 {
			return ops[1:]
		}
	case "dd":
		for _, a := range args {
			if strings.HasPrefix(a, "of=") {
				return []string{strings.TrimPrefix(a, "of=")}
			}
		}
	case "curl", "wget":
		for i, a := range args {
			if (a == "-o" || a == "--output" || a == "-O" && name == "wget") && i+1 < len(args) {
				return []string{args[i+1]}
			}
		}
	}
	return nil
}
