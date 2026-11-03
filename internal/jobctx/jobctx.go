// Package jobctx answers the questions a maintainer asks first when an agent
// misbehaves: who triggered this run, can that person be trusted, what input
// of theirs reached the agent, which agent ran, and what could its token do.
package jobctx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ChelateSec/titra/internal/miniyaml"
)

// Context is the "who and why" of one job.
type Context struct {
	Repo         string            `json:"repo,omitempty"`
	Workflow     string            `json:"workflow,omitempty"`
	WorkflowFile string            `json:"workflow_file,omitempty"`
	Job          string            `json:"job,omitempty"`
	RunID        string            `json:"run_id,omitempty"`
	RunURL       string            `json:"run_url,omitempty"`
	Event        string            `json:"event,omitempty"`
	Actor        string            `json:"actor,omitempty"`       // who caused the event
	Association  string            `json:"association,omitempty"` // OWNER, MEMBER, COLLABORATOR, CONTRIBUTOR, NONE, ...
	Trusted      bool              `json:"trusted"`
	TrustNote    string            `json:"trust_note,omitempty"`
	Untrusted    []string          `json:"untrusted_input,omitempty"` // which fields of outside input reached the job
	Subject      string            `json:"subject,omitempty"`         // "issue #42: title"
	Permissions  map[string]string `json:"permissions,omitempty"`
	PermNote     string            `json:"permissions_note,omitempty"`
	Agents       []string          `json:"agents,omitempty"`

	// Number is the issue or PR number the run is about ("" if none).
	Number string `json:"number,omitempty"`
	// ApprovedBy is the maintainer who approved this run by adding the approval
	// label. Only people with triage or write access can add labels on GitHub,
	// so an outsider can't approve their own run.
	ApprovedBy   string `json:"approved_by,omitempty"`
	ApproveLabel string `json:"approve_label,omitempty"`
}

// KnownAgentActions maps agent actions to a display name.
var KnownAgentActions = map[string]string{
	"anthropics/claude-code-action":        "Claude Code",
	"anthropics/claude-code-base-action":   "Claude Code",
	"google-github-actions/run-gemini-cli": "Gemini CLI",
	"openai/codex-action":                  "OpenAI Codex",
	"cline/cline":                          "Cline",
	"block/goose":                          "Goose",
	"sst/opencode":                         "OpenCode",
	"warpdotdev/warp-agent-action":         "Warp",
	"cursor/cursor-agent-action":           "Cursor",
}

// FromEnv builds the context from the GitHub Actions environment.
func FromEnv() Context {
	c := Context{
		Repo:     os.Getenv("GITHUB_REPOSITORY"),
		Workflow: os.Getenv("GITHUB_WORKFLOW"),
		Job:      os.Getenv("GITHUB_JOB"),
		RunID:    os.Getenv("GITHUB_RUN_ID"),
		Event:    os.Getenv("GITHUB_EVENT_NAME"),
		Actor:    first(os.Getenv("GITHUB_TRIGGERING_ACTOR"), os.Getenv("GITHUB_ACTOR")),
	}
	if srv := os.Getenv("GITHUB_SERVER_URL"); srv != "" && c.Repo != "" && c.RunID != "" {
		c.RunURL = srv + "/" + c.Repo + "/actions/runs/" + c.RunID
	}
	if p := os.Getenv("GITHUB_EVENT_PATH"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			var ev map[string]any
			if json.Unmarshal(b, &ev) == nil {
				c.applyEvent(ev)
			}
		}
	}
	c.applyWorkflow(os.Getenv("GITHUB_WORKSPACE"), os.Getenv("GITHUB_WORKFLOW_REF"))
	c.ApprovedBy = os.Getenv("TITRA_APPROVED_BY")
	c.ApproveLabel = os.Getenv("TITRA_APPROVE_LABEL")
	return c
}

func (c *Context) applyEvent(ev map[string]any) {
	issue := obj(ev, "issue")
	comment := obj(ev, "comment")
	pr := obj(ev, "pull_request")
	review := obj(ev, "review")
	disc := obj(ev, "discussion")
	if s := str(obj(ev, "sender"), "login"); s != "" {
		c.Actor = s
	}
	// On a "labeled" run the sender is the maintainer who added the label; the
	// person whose input the agent reads is still the issue or PR author.
	if str(ev, "action") == "labeled" {
		if a := str(obj(first2(issue, pr), "user"), "login"); a != "" {
			c.Actor = a
		}
	}
	if n := str(first2(issue, pr), "number"); n != "" {
		c.Number = n
	}

	switch c.Event {
	case "issues":
		c.Association = str(issue, "author_association")
		c.Subject = subject("issue", issue)
		c.Untrusted = []string{"issue title", "issue body"}
	case "issue_comment":
		c.Association = str(comment, "author_association")
		kind := "issue"
		if obj(issue, "pull_request") != nil {
			kind = "PR"
		}
		c.Subject = subject(kind, issue)
		c.Untrusted = []string{"comment body", kind + " title", kind + " body"}
	case "pull_request_review_comment":
		c.Association = str(comment, "author_association")
		c.Subject = subject("PR", pr)
		c.Untrusted = []string{"review comment body", "PR title", "PR body", "PR code"}
	case "pull_request_review":
		c.Association = str(review, "author_association")
		c.Subject = subject("PR", pr)
		c.Untrusted = []string{"review body", "PR title", "PR body", "PR code"}
	case "pull_request", "pull_request_target":
		c.Association = str(pr, "author_association")
		c.Subject = subject("PR", pr)
		c.Untrusted = []string{"PR title", "PR body", "PR branch name", "PR code"}
		head := str(obj(obj(pr, "head"), "repo"), "full_name")
		if head != "" && c.Repo != "" && head != c.Repo {
			c.Untrusted = append(c.Untrusted, "fork: "+head)
		}
	case "discussion", "discussion_comment":
		if comment != nil {
			c.Association = str(comment, "author_association")
		} else {
			c.Association = str(disc, "author_association")
		}
		c.Subject = subject("discussion", disc)
		c.Untrusted = []string{"discussion title", "discussion body"}
	}

	switch c.Event {
	case "push", "schedule", "workflow_dispatch", "release", "workflow_call", "repository_dispatch":
		c.Trusted = true
		c.TrustNote = "started by someone with write access"
		c.Untrusted = nil
		return
	case "workflow_run":
		c.Trusted = false
		c.TrustNote = "follows another workflow run, which may have run untrusted code"
		return
	}
	switch c.Association {
	case "OWNER", "MEMBER", "COLLABORATOR":
		c.Trusted = true
		c.TrustNote = strings.ToLower(c.Association) + " of the repository"
	case "":
		c.TrustNote = "unknown trigger"
	default:
		c.TrustNote = "outside contributor — anyone on GitHub can do this"
	}
}

// applyWorkflow reads the running workflow file for agents and permissions.
func (c *Context) applyWorkflow(workspace, ref string) {
	if workspace == "" || ref == "" {
		return
	}
	// owner/repo/.github/workflows/x.yml@refs/heads/main
	p := ref
	if i := strings.Index(p, "@"); i >= 0 {
		p = p[:i]
	}
	parts := strings.SplitN(p, "/", 3)
	if len(parts) < 3 {
		return
	}
	c.WorkflowFile = parts[2]
	b, err := os.ReadFile(filepath.Join(workspace, parts[2]))
	if err != nil {
		return
	}
	tree, err := miniyaml.Unmarshal(b)
	if err != nil {
		// Real workflows often use YAML the small parser can't read (run: |
		// blocks, flow lists). Fall back to line scanners that only need
		// indentation, so permissions and agents are still reported.
		c.Agents = scanUses(string(b))
		if perms, src, ok := scanPermissions(string(b), c.Job); ok {
			c.Permissions, c.PermNote = perms, "declared in "+src
		} else {
			c.PermNote = "not declared — uses the repository default, which may be write-all"
		}
		return
	}
	root, _ := tree.(map[string]any)
	jobs, _ := root["jobs"].(map[string]any)
	job, _ := jobs[c.Job].(map[string]any)

	perms, src := job["permissions"], "job"
	if perms == nil {
		perms, src = root["permissions"], "workflow"
	}
	switch v := perms.(type) {
	case nil:
		c.PermNote = "not declared — uses the repository default, which may be write-all"
	case string:
		c.Permissions = map[string]string{"all": strings.TrimSuffix(v, "-all")}
		c.PermNote = "declared in " + src
	case map[string]any:
		c.Permissions = map[string]string{}
		for k, val := range v {
			c.Permissions[k] = str(map[string]any{"v": val}, "v")
		}
		c.PermNote = "declared in " + src
	}

	if steps, ok := job["steps"].([]any); ok {
		for _, s := range steps {
			if sm, ok := s.(map[string]any); ok {
				if u := str(sm, "uses"); u != "" {
					if name := agentFor(u); name != "" {
						c.addAgent(name + " (" + u + ")")
					}
				}
			}
		}
	}
	if len(c.Agents) == 0 {
		for _, a := range scanUses(string(b)) {
			c.addAgent(a)
		}
	}
}

// AddAgent records an agent spotted at runtime (process name or hook).
func (c *Context) AddAgent(name string) { c.addAgent(name) }

func (c *Context) addAgent(name string) {
	base := strings.SplitN(name, " (", 2)[0]
	for _, a := range c.Agents {
		if strings.SplitN(a, " (", 2)[0] == base {
			return
		}
	}
	c.Agents = append(c.Agents, name)
	sort.Strings(c.Agents)
}

// WriteAccess lists permissions granted write.
func (c Context) WriteAccess() []string {
	var out []string
	for k, v := range c.Permissions {
		if v == "write" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// AgentFor returns the display name of the AI agent a `uses:` reference runs,
// or "" if it is not a known agent action.
func AgentFor(uses string) string { return agentFor(uses) }

func agentFor(uses string) string {
	u := strings.ToLower(strings.SplitN(uses, "@", 2)[0])
	for k, v := range KnownAgentActions {
		if u == k || strings.HasPrefix(u, k+"/") {
			return v
		}
	}
	return ""
}

func scanUses(src string) []string {
	var out []string
	for _, l := range strings.Split(src, "\n") {
		l = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "- "))
		if strings.HasPrefix(l, "uses:") {
			u := strings.Trim(strings.TrimSpace(strings.TrimPrefix(l, "uses:")), `"'`)
			if name := agentFor(u); name != "" {
				out = append(out, name+" ("+u+")")
			}
		}
	}
	return out
}

func subject(kind string, o map[string]any) string {
	if o == nil {
		return ""
	}
	n := str(o, "number")
	t := str(o, "title")
	if len(t) > 80 {
		t = t[:77] + "..."
	}
	if n == "" {
		return kind + ": " + t
	}
	return kind + " #" + n + ": " + t
}

func obj(m map[string]any, k string) map[string]any {
	if m == nil {
		return nil
	}
	v, _ := m[k].(map[string]any)
	return v
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	switch v := m[k].(type) {
	case string:
		return v
	case float64:
		return jsonNum(v)
	case int64:
		return jsonNum(float64(v))
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

func jsonNum(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}

func first(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func first2(a, b map[string]any) map[string]any {
	if a != nil {
		return a
	}
	return b
}
