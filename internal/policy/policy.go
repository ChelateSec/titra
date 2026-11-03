// Package policy defines Titra's policy model and loads it from a YAML (or JSON)
// file. A policy is a list of ordered rules evaluated against each action an AI
// agent attempts inside a CI job.
package policy

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/ChelateSec/titra/internal/miniyaml"
)

// Mode controls how far the guard goes when a rule says "block".
type Mode string

const (
	// ModeMonitor logs every action and blocks nothing. The safe first step:
	// see what your agents do before you enforce anything.
	ModeMonitor Mode = "monitor"
	// ModeDryRun logs what it *would* block, but still lets the action run.
	ModeDryRun Mode = "dry-run"
	// ModeEnforce logs and actually blocks matching actions.
	ModeEnforce Mode = "enforce"
)

// Action is the verdict a rule assigns to a matching action.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Severity ranks a finding. Ordered so they can be compared numerically.
type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

var sevRank = map[Severity]int{
	SevInfo: 0, SevLow: 1, SevMedium: 2, SevHigh: 3, SevCritical: 4,
}

// AtLeast reports whether s is at least as severe as min.
func (s Severity) AtLeast(min Severity) bool {
	return sevRank[s] >= sevRank[min]
}

// Match is the condition part of a rule. A rule matches when every non-empty
// field matches the action.
type Match struct {
	// Tool matches the invoked command name exactly (e.g. "git", "gh", "curl").
	// Empty means "any tool".
	Tool string
	// ArgsRegex is a regular expression tested against the space-joined
	// arguments. Empty means "any arguments".
	ArgsRegex string

	argsRe *regexp.Regexp // compiled form of ArgsRegex
}

// Rule is one ordered policy entry.
type Rule struct {
	ID          string
	Description string
	Action      Action
	Severity    Severity
	Match       Match
}

// Policy is the whole ruleset plus top-level settings.
type Policy struct {
	Version int
	Mode    Mode
	// Default is the verdict when no rule matches. Almost always "allow".
	Default Action
	Rules   []Rule
	// AllowedDomains are extra network destinations this workflow is expected
	// to reach, on top of Titra's built-in list (GitHub, package registries,
	// model APIs). "*.example.com" matches any subdomain.
	AllowedDomains []string
	// Writes limits where an agent may write: "workspace" (default: inside the
	// repository checkout only, never .git/ or workflow files) or "any".
	Writes string
}

// Default returns Titra's built-in secure-default policy. It is compiled into
// the binary so the guard always has something sane even with no policy file.
// These defaults protect the actions that turned real 2026 incidents into
// supply-chain compromises: pushing code, approving/merging PRs, rewriting
// workflow or agent-config files, and reaching an unexpected network endpoint.
func Default() *Policy {
	return &Policy{
		Version: 1,
		Mode:    ModeMonitor, // safe by default: observe first, enforce deliberately
		Default: ActionAllow,
		Rules: []Rule{
			{
				ID:          "block-git-push",
				Description: "Agent must not push code to the repository",
				Action:      ActionBlock,
				Severity:    SevCritical,
				Match:       Match{Tool: "git", ArgsRegex: `(^|\s)push(\s|$)`},
			},
			{
				ID:          "block-pr-approval",
				Description: "Agent must not approve or merge pull requests",
				Action:      ActionBlock,
				Severity:    SevCritical,
				Match:       Match{Tool: "gh", ArgsRegex: `pr\s+(review|merge)`},
			},
			{
				ID:          "block-workflow-dispatch",
				Description: "Agent must not trigger other workflows (pivot path)",
				Action:      ActionBlock,
				Severity:    SevHigh,
				Match:       Match{Tool: "gh", ArgsRegex: `workflow\s+run|actions/workflows/.+/dispatches`},
			},
			{
				ID:          "block-release-publish",
				Description: "Agent must not publish packages or releases",
				Action:      ActionBlock,
				Severity:    SevCritical,
				Match:       Match{ArgsRegex: `(^|\s)(npm|pnpm|yarn)\s+publish|gh\s+release\s+create|twine\s+upload`},
			},
			{
				ID:          "block-untrusted-package-source",
				Description: "Agent must not install packages straight from a git repo or URL (not a registry)",
				Action:      ActionBlock,
				Severity:    SevCritical,
				Match:       Match{ArgsRegex: `(^|\s)(npm|pnpm|yarn|bun)\s+(install|i|add|ci)\b.*(git\+|github:|gitlab:|bitbucket:|https?://)|(^|\s)npx\s+.*(git\+|github:|gitlab:|https?://)|(^|\s)pip3?\s+install\b.*(git\+|https?://)`},
			},
			{
				ID:          "flag-credential-read",
				Description: "Agent read a credential store (likely exfiltration prep)",
				Action:      ActionBlock,
				Severity:    SevHigh,
				Match:       Match{ArgsRegex: `\.git/config|/proc/\d+/environ|\.npmrc|\.env(\s|$)|id_rsa`},
			},
		},
	}
}

// Load reads a policy from path. .json files are parsed as JSON; everything
// else is parsed as the YAML subset. Missing fields fall back to Default().
func Load(path string) (*Policy, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var tree any
	if strings.HasSuffix(path, ".json") {
		if err := json.Unmarshal(raw, &tree); err != nil {
			return nil, fmt.Errorf("policy %s: %w", path, err)
		}
	} else {
		tree, err = miniyaml.Unmarshal(raw)
		if err != nil {
			return nil, fmt.Errorf("policy %s: %w", path, err)
		}
	}
	p, err := fromTree(tree)
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	if err := p.compile(); err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return p, nil
}

// Parse reads a policy from YAML (or JSON, which is a YAML subset for our
// purposes) bytes. The server uses it to validate an org policy before saving.
func Parse(raw []byte) (*Policy, error) {
	var tree any
	if t := strings.TrimSpace(string(raw)); strings.HasPrefix(t, "{") {
		if err := json.Unmarshal(raw, &tree); err != nil {
			return nil, err
		}
	} else {
		var err error
		if tree, err = miniyaml.Unmarshal(raw); err != nil {
			return nil, err
		}
	}
	p, err := fromTree(tree)
	if err != nil {
		return nil, err
	}
	if err := p.compile(); err != nil {
		return nil, err
	}
	return p, nil
}

// compile builds the regexps and validates enum values. Always call before use;
// Default() values are static and compiled lazily on first Load, so callers of
// Default() should call compile() too (Engine does).
func (p *Policy) compile() error {
	if p.Mode == "" {
		p.Mode = ModeMonitor
	}
	switch p.Mode {
	case ModeMonitor, ModeDryRun, ModeEnforce:
	default:
		return fmt.Errorf("invalid mode %q (want monitor|dry-run|enforce)", p.Mode)
	}
	if p.Default == "" {
		p.Default = ActionAllow
	}
	switch p.Writes {
	case "", "workspace", "any":
	default:
		return fmt.Errorf("invalid writes %q (want workspace|any)", p.Writes)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" {
			return fmt.Errorf("rule %d: missing id", i)
		}
		if r.Action == "" {
			r.Action = ActionBlock
		}
		if r.Severity == "" {
			r.Severity = SevMedium
		}
		if r.Match.ArgsRegex != "" {
			re, err := regexp.Compile(r.Match.ArgsRegex)
			if err != nil {
				return fmt.Errorf("rule %q: bad args_regex: %w", r.ID, err)
			}
			r.Match.argsRe = re
		}
	}
	return nil
}

// Compile exposes compile for callers that build a Policy in code (e.g. Default).
func (p *Policy) Compile() error { return p.compile() }

// Regexp returns the compiled args regex for a match, or nil if the match has
// none. Valid only after the owning Policy has been compiled.
func (m Match) Regexp() *regexp.Regexp { return m.argsRe }

func fromTree(tree any) (*Policy, error) {
	if tree == nil {
		return Default(), nil
	}
	m, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("top level must be a mapping")
	}
	p := &Policy{
		Version: asInt(m["version"], 1),
		Mode:    Mode(asStr(m["mode"], "")),
		Default: Action(asStr(m["default"], "")),
		Writes:  asStr(m["writes"], ""),
	}
	if ds, ok := m["allowed_domains"].([]any); ok {
		for _, d := range ds {
			if v := asStr(d, ""); v != "" {
				p.AllowedDomains = append(p.AllowedDomains, v)
			}
		}
	}
	rulesAny, _ := m["rules"].([]any)
	for i, ra := range rulesAny {
		rm, ok := ra.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rule %d must be a mapping", i)
		}
		r := Rule{
			ID:          asStr(rm["id"], ""),
			Description: asStr(rm["description"], ""),
			Action:      Action(asStr(rm["action"], "")),
			Severity:    Severity(asStr(rm["severity"], "")),
		}
		if mm, ok := rm["match"].(map[string]any); ok {
			r.Match = Match{
				Tool:      asStr(mm["tool"], ""),
				ArgsRegex: asStr(mm["args_regex"], ""),
			}
		}
		p.Rules = append(p.Rules, r)
	}
	return p, nil
}

func asStr(v any, def string) string {
	if s, ok := v.(string); ok {
		return s
	}
	if v == nil {
		return def
	}
	return fmt.Sprintf("%v", v)
}

func asInt(v any, def int) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case float64:
		return int(n)
	case int:
		return n
	}
	return def
}
