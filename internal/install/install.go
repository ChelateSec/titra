// Package install sets Titra up inside a CI job. It creates a directory of
// symlinks — one per guarded tool, each pointing at the Titra binary — and emits
// the environment that puts that directory first on PATH. After install, every
// `git`, `gh`, `curl`, ... the agent runs resolves to Titra first.
//
// It emits two things:
//   - `export VAR=value` lines on stdout, so `eval "$(titra install ...)"` works
//     in a local shell or a plain CI step.
//   - the same values appended to $GITHUB_PATH / $GITHUB_ENV when --github-env is
//     set, so a GitHub Actions composite step wires it into later steps.
package install

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func randRunID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return "local-" + hex.EncodeToString(b)
}

// DefaultTools are the high-value commands Titra guards out of the box: code
// push, PR approval/merge, package publish, network egress, credential stores.
// Shells (bash/sh) are deliberately excluded — their inner commands are already
// intercepted, and shimming the shell itself adds noise and risk.
var DefaultTools = []string{
	"git", "gh", "curl", "wget",
	"npm", "npx", "pnpm", "yarn",
	"pip", "pip3", "python", "python3", "node",
}

// Options configures an install.
type Options struct {
	Dir        string   // where to create the shim symlinks
	Tools      []string // tool names to guard
	LogPath    string   // TITRA_LOG value to emit
	PolicyPath string   // TITRA_POLICY value to emit (optional)
	Mode       string   // TITRA_MODE value to emit (optional)
	Server     string   // TITRA_SERVER value to emit (optional): stream actions here
	Token      string   // TITRA_TOKEN value to emit (optional): ingest auth
	Project    string   // TITRA_PROJECT value to emit (optional): dashboard grouping
	GitHubEnv  bool     // also append to $GITHUB_PATH / $GITHUB_ENV
}

// Run performs the install and writes the environment. It returns the resolved
// shim directory.
func Run(self string, opt Options) (string, error) {
	dir, err := filepath.Abs(opt.Dir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}

	tools := opt.Tools
	if len(tools) == 0 {
		tools = DefaultTools
	}
	for _, t := range tools {
		link := filepath.Join(dir, t)
		_ = os.Remove(link) // replace any stale link
		if err := os.Symlink(self, link); err != nil {
			return "", fmt.Errorf("linking %s: %w", t, err)
		}
	}

	env := map[string]string{
		"TITRA_SHIM_DIR": dir,
		"TITRA_LOG":      opt.LogPath,
		// Group this job's actions into one run on the dashboard. Prefer the
		// GitHub run id; fall back to a generated id for local/other CI.
		"TITRA_RUN_ID": firstNonEmpty(os.Getenv("GITHUB_RUN_ID"), os.Getenv("TITRA_RUN_ID"), randRunID()),
	}
	if opt.PolicyPath != "" {
		env["TITRA_POLICY"] = opt.PolicyPath
	}
	if opt.Mode != "" {
		env["TITRA_MODE"] = opt.Mode
	}
	if opt.Server != "" {
		env["TITRA_SERVER"] = opt.Server
	}
	if opt.Token != "" {
		env["TITRA_TOKEN"] = opt.Token
	}
	if opt.Project != "" {
		env["TITRA_PROJECT"] = opt.Project
	}

	// Emit shell exports so `eval "$(titra install ...)"` works anywhere.
	var b strings.Builder
	fmt.Fprintf(&b, "export PATH=%q\n", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	for k, v := range env {
		fmt.Fprintf(&b, "export %s=%q\n", k, v)
	}
	fmt.Print(b.String())

	if opt.GitHubEnv {
		if err := writeGitHubEnv(dir, env); err != nil {
			return "", err
		}
	}
	return dir, nil
}

// writeGitHubEnv wires the shim dir onto PATH and the Titra vars into the env
// for every later step, using the files GitHub Actions exposes.
func writeGitHubEnv(dir string, env map[string]string) error {
	if p := os.Getenv("GITHUB_PATH"); p != "" {
		if err := appendLine(p, dir); err != nil {
			return err
		}
	}
	if e := os.Getenv("GITHUB_ENV"); e != "" {
		for k, v := range env {
			if err := appendLine(e, k+"="+v); err != nil {
				return err
			}
		}
	}
	return nil
}

func appendLine(path, line string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintln(f, line)
	return err
}
