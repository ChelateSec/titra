// Package engine evaluates an attempted agent action against a policy and
// returns a decision. The decision is deterministic: it is plain rule matching,
// never a model. That is the point — a guard that asked an LLM whether to block
// could itself be prompt-injected, reintroducing the very risk Titra removes.
package engine

import (
	"strings"

	"github.com/ChelateSec/titra/internal/policy"
)

// Attempt describes one action an agent tried to take: a tool invocation.
type Attempt struct {
	Tool string   // command name, e.g. "git"
	Args []string // its arguments
}

// ArgString is the canonical space-joined argument string that rules match on.
func (a Attempt) ArgString() string { return strings.Join(a.Args, " ") }

// Verdict is the enforced outcome for an attempt.
type Verdict string

const (
	// VerdictAllow: the action runs.
	VerdictAllow Verdict = "allow"
	// VerdictBlock: the action is refused (enforce mode only).
	VerdictBlock Verdict = "block"
	// VerdictWouldBlock: a block rule matched but mode is monitor/dry-run, so
	// the action still runs. This is the signal teams watch before enforcing.
	VerdictWouldBlock Verdict = "would-block"
)

// Decision is the full result of evaluating an attempt.
type Decision struct {
	Verdict  Verdict
	RuleID   string // the rule that decided it, "" for the policy default
	Severity policy.Severity
	Reason   string // human-readable description from the rule
	Mode     policy.Mode
}

// Blocked reports whether the action was actually prevented.
func (d Decision) Blocked() bool { return d.Verdict == VerdictBlock }

// Engine evaluates attempts against a fixed policy.
type Engine struct {
	pol *policy.Policy
}

// New returns an Engine over a policy. It compiles the policy (idempotent) so
// in-code policies such as policy.Default() are ready to use without the caller
// remembering to compile. A compile error here means a programming bug in a
// built-in policy; Load already validates file-based policies.
func New(p *policy.Policy) (*Engine, error) {
	if err := p.Compile(); err != nil {
		return nil, err
	}
	return &Engine{pol: p}, nil
}

// Policy returns the underlying policy.
func (e *Engine) Policy() *policy.Policy { return e.pol }

// Evaluate finds the first matching rule and applies the mode to produce a
// verdict. First match wins, in policy order.
func (e *Engine) Evaluate(a Attempt) Decision {
	for _, r := range e.pol.Rules {
		if ruleMatches(r, a) {
			return e.decide(r.Action, r.ID, r.Severity, reasonOf(r))
		}
	}
	// No rule matched: apply the default.
	return e.decide(e.pol.Default, "", policy.SevInfo, "no matching rule; policy default")
}

// Decide applies the policy's mode to a block decision made outside the rule
// list (a built-in check such as the write guard): block in enforce, would-block
// in monitor and dry-run.
func (e *Engine) Decide(ruleID string, sev policy.Severity, reason string) Decision {
	return e.decide(policy.ActionBlock, ruleID, sev, reason)
}

func reasonOf(r policy.Rule) string {
	if r.Description != "" {
		return r.Description
	}
	return "matched rule " + r.ID
}

// decide maps a rule action + severity + the policy mode into a Verdict.
func (e *Engine) decide(act policy.Action, ruleID string, sev policy.Severity, reason string) Decision {
	d := Decision{RuleID: ruleID, Severity: sev, Reason: reason, Mode: e.pol.Mode}
	if act != policy.ActionBlock {
		d.Verdict = VerdictAllow
		return d
	}
	// A block rule matched. Whether we actually block depends on mode.
	switch e.pol.Mode {
	case policy.ModeEnforce:
		d.Verdict = VerdictBlock
	default: // monitor, dry-run
		d.Verdict = VerdictWouldBlock
	}
	return d
}

// ruleMatches reports whether an attempt satisfies a rule's Match. A rule with
// a Tool matches only that tool; a rule with no Tool matches any tool and tests
// its regex against the full "tool args" string so cross-tool patterns work.
func ruleMatches(r policy.Rule, a Attempt) bool {
	if r.Match.Tool != "" {
		if r.Match.Tool != a.Tool {
			return false
		}
		if re := r.Match.Regexp(); re != nil {
			return re.MatchString(a.ArgString())
		}
		return true
	}
	// Tool-agnostic rule: match against "tool args" so patterns can name the
	// tool themselves (e.g. an npm-publish rule that could fire under any shell).
	if re := r.Match.Regexp(); re != nil {
		return re.MatchString(strings.TrimSpace(a.Tool + " " + a.ArgString()))
	}
	return true // no tool, no regex: matches everything (rarely wanted)
}
