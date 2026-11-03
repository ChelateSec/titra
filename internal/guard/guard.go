// Package guard is the enforcement point: the code that runs when an AI agent
// in CI invokes a command Titra intercepts. Titra installs itself on PATH under
// the names of the tools it guards (git, gh, curl, ...), busybox-style. When the
// agent runs `git push`, it is Titra that runs — it evaluates the attempt against
// the policy, records it, then either executes the real tool or refuses.
//
// The decision is deterministic policy matching, never a model. A guard that
// asked an LLM whether to block could itself be prompt-injected, reintroducing
// the exact risk Titra exists to remove.
package guard

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ChelateSec/titra/internal/audit"
	"github.com/ChelateSec/titra/internal/engine"
	"github.com/ChelateSec/titra/internal/policy"
	"github.com/ChelateSec/titra/internal/reporter"
)

// Config is resolved from the environment Titra's installer sets up in the job.
type Config struct {
	LogPath      string      // TITRA_LOG: where to append the JSONL action log
	PolicyPath   string      // TITRA_POLICY: optional policy file; built-in used if empty
	ModeOverride policy.Mode // TITRA_MODE: overrides the policy file's mode if set
	ShimDir      string      // TITRA_SHIM_DIR: the dir of Titra symlinks, skipped on lookup
}

// ConfigFromEnv reads Titra's configuration from the process environment.
func ConfigFromEnv() Config {
	return Config{
		LogPath:      os.Getenv("TITRA_LOG"),
		PolicyPath:   os.Getenv("TITRA_POLICY"),
		ModeOverride: policy.Mode(os.Getenv("TITRA_MODE")),
		ShimDir:      os.Getenv("TITRA_SHIM_DIR"),
	}
}

// LoadPolicy builds the effective policy: a file if TITRA_POLICY points at one,
// otherwise the compiled-in secure default. If the file is broken it returns
// the default policy AND the error, so callers keep protecting while they warn. A TITRA_MODE env var overrides the
// mode either way, so a workflow can flip monitor -> enforce without editing the
// policy file.
func LoadPolicy(cfg Config) (*policy.Policy, error) {
	var p *policy.Policy
	var loadErr error
	if cfg.PolicyPath != "" {
		if _, err := os.Stat(cfg.PolicyPath); err == nil {
			loaded, err := policy.Load(cfg.PolicyPath)
			if err != nil {
				// A broken policy must never switch protection off. Fall back to
				// the built-in rules and report the error alongside.
				loadErr = err
			} else {
				p = loaded
			}
		}
	}
	if p == nil {
		p = policy.Default()
	}
	if cfg.ModeOverride != "" {
		p.Mode = cfg.ModeOverride
	}
	if err := p.Compile(); err != nil {
		return nil, err
	}
	return p, loadErr
}

// Run guards a single tool invocation. It is called both when Titra is invoked
// via a tool-named symlink (tool = "git", args = the git args) and from the
// `titra guard <tool> <args...>` subcommand. It never returns on success: it
// either execs the real tool (replacing this process) or exits with a non-zero
// status after blocking.
func Run(tool string, args []string) {
	cfg := ConfigFromEnv()

	pol, err := LoadPolicy(cfg)
	if pol == nil {
		// Only the compiled-in defaults failed, which is a build bug. Don't
		// break the pipeline over it.
		fmt.Fprintf(os.Stderr, "titra: internal policy error: %v (allowing %s)\n", err, tool)
		execReal(cfg, tool, args)
		return
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "titra: policy error: %v — using Titra's built-in rules instead\n", err)
	}

	eng, err := engine.New(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "titra: engine error: %v (allowing %s)\n", err, tool)
		execReal(cfg, tool, args)
		return
	}

	attempt := engine.Attempt{Tool: tool, Args: args}
	decision := eng.Evaluate(attempt)

	// Build the record once; write it to the local log and stream it to the
	// Titra server. Both are best-effort — a failure to record must never break
	// the build or the agent.
	rec := audit.NewRecord(attempt, decision)
	if cfg.LogPath != "" {
		if logger, err := audit.Open(cfg.LogPath); err == nil {
			_ = logger.Append(rec)
		}
	}
	reporter.Report(rec)

	if decision.Blocked() {
		printBlock(tool, args, decision)
		os.Exit(1)
	}

	if decision.Verdict == engine.VerdictWouldBlock {
		// Visible in the live log, but the action still runs. This is the signal
		// teams watch during monitor / dry-run before they flip to enforce.
		fmt.Fprintf(os.Stderr, "titra: WOULD BLOCK %s %s  [%s/%s] %s\n",
			tool, strings.Join(args, " "), decision.RuleID, decision.Severity, decision.Reason)
	}

	execReal(cfg, tool, args)
}

// printBlock writes the refusal to stderr in a form that stands out in a CI log.
func printBlock(tool string, args []string, d engine.Decision) {
	cmd := strings.TrimSpace(tool + " " + strings.Join(args, " "))
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  ╳ titra BLOCKED  %s\n", cmd)
	fmt.Fprintf(os.Stderr, "    rule:     %s (%s)\n", d.RuleID, d.Severity)
	fmt.Fprintf(os.Stderr, "    reason:   %s\n", d.Reason)
	fmt.Fprintf(os.Stderr, "    this action was refused before it ran. (titra mode: %s)\n\n", d.Mode)
}

// execReal finds the genuine tool on PATH (excluding Titra's own shim dir) and
// runs it transparently in place of this process. On Linux it uses execve so
// the real tool inherits the pid, stdio, signals and exit code exactly.
func execReal(cfg Config, tool string, args []string) {
	real, err := resolveReal(tool, cfg.ShimDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "titra: %v\n", err)
		os.Exit(127)
	}

	// Transparent exec: replace this process with the real tool. We pass the
	// bare tool name as argv[0] (not the resolved absolute path) on purpose: it
	// is the conventional argv[0], and it lets the kernel-trace layer tell a
	// shim-routed run (argv[0] = "git") apart from a bypass that invoked the
	// real binary directly by path (argv[0] = "/usr/bin/git").
	argv := append([]string{tool}, args...)
	execErr := syscall.Exec(real, argv, os.Environ())
	if execErr == nil {
		return // unreachable on success
	}

	// Fallback for platforms where Exec isn't available: subprocess with
	// inherited stdio, forwarding the exit code.
	c := exec.Command(real, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if runErr := c.Run(); runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			os.Exit(ee.ExitCode())
		}
		fmt.Fprintf(os.Stderr, "titra: failed to run %s: %v\n", tool, runErr)
		os.Exit(1)
	}
	os.Exit(0)
}

// resolveReal returns the path to the genuine tool binary: the first executable
// named `tool` on PATH that is neither inside Titra's shim dir nor another
// symlink back to the Titra binary itself. This is what lets `git` (a symlink to
// titra) find and run the real git.
func resolveReal(tool, shimDir string) (string, error) {
	self := selfPath()
	shim := cleanDir(shimDir)

	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if cleanDir(dir) == shim {
			continue // never resolve back into our own shim dir
		}
		cand := filepath.Join(dir, tool)
		if !isExecutableFile(cand) {
			continue
		}
		if resolved, err := filepath.EvalSymlinks(cand); err == nil && resolved == self {
			continue // a stray symlink pointing back at titra
		}
		return cand, nil
	}
	return "", fmt.Errorf("real %q not found on PATH (outside the titra shim dir)", tool)
}

// selfPath returns the resolved path to the running Titra binary.
func selfPath() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		return resolved
	}
	return exe
}

func cleanDir(d string) string {
	if d == "" {
		return ""
	}
	abs, err := filepath.Abs(d)
	if err != nil {
		return filepath.Clean(d)
	}
	return abs
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}
