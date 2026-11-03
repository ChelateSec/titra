package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallLinksToolsAndWritesGitHubEnv(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "titra")
	_ = os.WriteFile(self, []byte("#!/bin/sh\n"), 0o755)
	ghEnv, ghPath := filepath.Join(dir, "env"), filepath.Join(dir, "path")
	_ = os.WriteFile(ghEnv, nil, 0o644)
	_ = os.WriteFile(ghPath, nil, 0o644)
	t.Setenv("GITHUB_ENV", ghEnv)
	t.Setenv("GITHUB_PATH", ghPath)
	t.Setenv("GITHUB_RUN_ID", "42")

	shims := filepath.Join(dir, "shims")
	got, err := Run(self, Options{Dir: shims, Tools: []string{"git", "npm"}, LogPath: "/tmp/l", Mode: "enforce",
		Server: "https://d.example", Token: "ttr_x", GitHubEnv: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"git", "npm"} {
		target, err := os.Readlink(filepath.Join(got, tool))
		if err != nil || target != self {
			t.Fatalf("%s should link to titra: %q %v", tool, target, err)
		}
	}
	p, _ := os.ReadFile(ghPath)
	if strings.TrimSpace(string(p)) != got {
		t.Fatalf("GITHUB_PATH should get the shim dir, got %q", p)
	}
	e, _ := os.ReadFile(ghEnv)
	for _, want := range []string{"TITRA_MODE=enforce", "TITRA_RUN_ID=42", "TITRA_SERVER=https://d.example", "TITRA_TOKEN=ttr_x", "TITRA_SHIM_DIR=" + got} {
		if !strings.Contains(string(e), want) {
			t.Fatalf("GITHUB_ENV missing %q:\n%s", want, e)
		}
	}
}

func TestReinstallReplacesStaleLinks(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "titra")
	_ = os.WriteFile(self, []byte("x"), 0o755)
	shims := filepath.Join(dir, "shims")
	_ = os.MkdirAll(shims, 0o755)
	_ = os.Symlink("/old/titra", filepath.Join(shims, "git"))
	if _, err := Run(self, Options{Dir: shims, Tools: []string{"git"}}); err != nil {
		t.Fatal(err)
	}
	if target, _ := os.Readlink(filepath.Join(shims, "git")); target != self {
		t.Fatalf("stale link not replaced: %s", target)
	}
}
