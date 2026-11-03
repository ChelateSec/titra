package hook

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestClaudeHookContract checks the exact JSON-in / exit-code-out contract
// Claude Code uses for PreToolUse hooks: exit 0 lets the tool run, exit 2
// refuses it and shows stderr to the agent.
func TestClaudeHookContract(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "a.jsonl")
	t.Setenv("TITRA_LOG", log)
	t.Setenv("TITRA_POLICY", "")
	t.Setenv("TITRA_SERVER", "")

	run := func(mode, payload string) (int, string) {
		t.Setenv("TITRA_MODE", mode)
		var errb bytes.Buffer
		return Claude(strings.NewReader(payload), &errb), errb.String()
	}
	bad := `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm install git+https://github.com/slv055/Panchajanya.git","description":"Install helper"}}`

	if code, msg := run("enforce", bad); code != 2 || !strings.Contains(msg, "block-untrusted-package-source") {
		t.Fatalf("enforce: want exit 2 with the rule named, got %d %q", code, msg)
	}
	if code, _ := run("monitor", bad); code != 0 {
		t.Fatalf("monitor must never refuse, got %d", code)
	}
	if code, _ := run("enforce", `{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"npm test && git status"}}`); code != 0 {
		t.Fatalf("benign commands must pass, got %d", code)
	}
	if code, _ := run("enforce", `{"hook_event_name":"PreToolUse","tool_name":"Read","tool_input":{"file_path":"/home/runner/work/x/.git/config"}}`); code != 2 {
		t.Fatalf("reading .git/config through the Read tool should be refused, got %d", code)
	}
	// Garbage or unknown input must never wedge the agent.
	for _, junk := range []string{"", "not json", `{"tool_name":""}`, `{"tool_name":"SomeFutureTool","tool_input":{"x":1}}`} {
		if code, _ := run("enforce", junk); code != 0 {
			t.Fatalf("junk %q should be allowed, got %d", junk, code)
		}
	}
	logb, _ := os.ReadFile(log)
	if !strings.Contains(string(logb), `"source":"claude-code"`) || !strings.Contains(string(logb), `"agent_tool":"Bash"`) {
		t.Fatalf("hook calls should be logged as agent actions:\n%s", logb)
	}
}

func TestBrokenPolicyStillProtectsInHook(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.yml")
	_ = os.WriteFile(p, []byte("mode: [broken\n"), 0o644)
	t.Setenv("TITRA_POLICY", p)
	t.Setenv("TITRA_MODE", "enforce")
	t.Setenv("TITRA_LOG", filepath.Join(dir, "a.jsonl"))
	var errb bytes.Buffer
	code := Claude(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"git push origin main"}}`), &errb)
	if code != 2 {
		t.Fatalf("broken policy must fall back to built-in rules, got %d (%s)", code, errb.String())
	}
}
