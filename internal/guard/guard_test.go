package guard

// These tests build the real titra binary, install its shims, and run commands
// through a shell the way a CI job does. The guard replaces its own process, so
// only an out-of-process test exercises it honestly.

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type rig struct {
	t       *testing.T
	titra   string
	shims   string
	realBin string
	log     string
	env     []string
}

func newRig(t *testing.T, mode string, policyYAML string) *rig {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shims are POSIX symlinks")
	}
	dir := t.TempDir()
	titra := filepath.Join(dir, "titra")
	build := exec.Command("go", "build", "-o", titra, "../..")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	// Fake "real" tools that print what they were asked to do.
	realBin := filepath.Join(dir, "real")
	_ = os.MkdirAll(realBin, 0o755)
	for _, tool := range []string{"git", "npm", "curl", "gh"} {
		script := "#!/bin/sh\necho REAL-" + tool + " \"$@\"\n"
		_ = os.WriteFile(filepath.Join(realBin, tool), []byte(script), 0o755)
	}
	shims := filepath.Join(dir, "shims")
	log := filepath.Join(dir, "actions.jsonl")
	r := &rig{t: t, titra: titra, shims: shims, realBin: realBin, log: log}
	r.env = []string{
		"PATH=" + shims + ":" + realBin + ":/usr/bin:/bin",
		"TITRA_SHIM_DIR=" + shims,
		"TITRA_LOG=" + log,
		"TITRA_MODE=" + mode,
		"HOME=" + dir,
	}
	if policyYAML != "" {
		p := filepath.Join(dir, "policy.yml")
		_ = os.WriteFile(p, []byte(policyYAML), 0o644)
		r.env = append(r.env, "TITRA_POLICY="+p)
	}
	inst := exec.Command(titra, "install", "--dir", shims, "--log", log, "--tools", "git,npm,curl,gh")
	inst.Env = r.env
	if out, err := inst.CombinedOutput(); err != nil {
		t.Fatalf("install: %v\n%s", err, out)
	}
	return r
}

func (r *rig) sh(cmd string) (string, int) {
	c := exec.Command("/bin/sh", "-c", cmd)
	c.Env = r.env
	out, err := c.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(out), code
}

func TestEnforceBlocksAndAllows(t *testing.T) {
	r := newRig(t, "enforce", "")
	out, code := r.sh("git push origin main")
	if code == 0 || strings.Contains(out, "REAL-git") || !strings.Contains(out, "titra BLOCKED") {
		t.Fatalf("git push should be blocked, got code %d:\n%s", code, out)
	}
	out, code = r.sh("git status")
	if code != 0 || !strings.Contains(out, "REAL-git status") {
		t.Fatalf("git status should reach the real git, got code %d:\n%s", code, out)
	}
	out, code = r.sh("npm install git+https://github.com/evil/x.git")
	if code == 0 || strings.Contains(out, "REAL-npm") {
		t.Fatalf("npm install from git should be blocked:\n%s", out)
	}
	out, code = r.sh("npm install lodash")
	if code != 0 || !strings.Contains(out, "REAL-npm install lodash") {
		t.Fatalf("registry npm install should pass:\n%s", out)
	}
}

func TestMonitorNeverBlocks(t *testing.T) {
	r := newRig(t, "monitor", "")
	out, code := r.sh("git push origin main")
	if code != 0 || !strings.Contains(out, "REAL-git push") || !strings.Contains(out, "WOULD BLOCK") {
		t.Fatalf("monitor should run the real tool and warn, got %d:\n%s", code, out)
	}
	logb, _ := os.ReadFile(r.log)
	if !strings.Contains(string(logb), `"verdict":"would-block"`) {
		t.Fatalf("would-block should be logged:\n%s", logb)
	}
}

func TestExitCodeAndArgsPassThrough(t *testing.T) {
	r := newRig(t, "enforce", "")
	_ = os.WriteFile(filepath.Join(r.realBin, "git"), []byte("#!/bin/sh\necho \"argc=$# 1=$1 2=$2\"\nexit 7\n"), 0o755)
	out, code := r.sh(`git log "--format=%H %s"`)
	if code != 7 || !strings.Contains(out, "argc=2 1=log 2=--format=%H %s") {
		t.Fatalf("args/exit code not passed through: code %d\n%s", code, out)
	}
}

func TestCustomPolicyFile(t *testing.T) {
	r := newRig(t, "", "version: 1\nmode: enforce\nrules:\n  - id: no-npm\n    action: block\n    match:\n      tool: npm\n")
	if out, code := r.sh("npm test"); code == 0 {
		t.Fatalf("policy blocks all npm:\n%s", out)
	}
	if out, code := r.sh("git push"); code != 0 {
		t.Fatalf("custom policy has no git rule; push should pass:\n%s", out)
	}
}

func TestBrokenPolicyFallsBackToBuiltInRules(t *testing.T) {
	r := newRig(t, "enforce", "mode: [not, valid\n")
	out, code := r.sh("git status")
	if code != 0 || !strings.Contains(out, "built-in rules") || !strings.Contains(out, "REAL-git status") {
		t.Fatalf("a broken policy should warn and keep running safe commands:\n%s", out)
	}
	out, code = r.sh("git push origin main")
	if code == 0 || strings.Contains(out, "REAL-git") {
		t.Fatalf("a broken policy must not switch protection off:\n%s", out)
	}
}

func TestNoRecursionWhenShimDirMissingFromEnv(t *testing.T) {
	r := newRig(t, "enforce", "")
	// A stray symlink to titra elsewhere on PATH must not resolve back to titra.
	stray := filepath.Join(filepath.Dir(r.shims), "stray")
	_ = os.MkdirAll(stray, 0o755)
	_ = os.Symlink(r.titra, filepath.Join(stray, "git"))
	r.env[0] = "PATH=" + r.shims + ":" + stray + ":" + r.realBin + ":/usr/bin:/bin"
	out, code := r.sh("git status")
	if code != 0 || !strings.Contains(out, "REAL-git status") {
		t.Fatalf("should skip the stray titra link and run real git, got %d:\n%s", code, out)
	}
}
