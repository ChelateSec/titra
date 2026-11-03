// Package audit writes an append-only, one-record-per-line JSON log of every
// action an agent attempted and what Titra decided. The log is the "see" half
// of Titra: a durable, machine-readable record of what ran inside the job. The
// same Record is both written to the local log and streamed to the Titra server,
// so the on-the-wire shape and the on-disk shape are one thing.
package audit

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/ChelateSec/titra/internal/engine"
)

// Record is one logged action + decision. The JSON shape is the on-the-wire
// contract: keep it stable, add fields rather than rename.
type Record struct {
	Time     string   `json:"time"`               // RFC3339 UTC
	Tool     string   `json:"tool"`               // command name
	Args     []string `json:"args"`               // its arguments
	Verdict  string   `json:"verdict"`            // allow | block | would-block
	RuleID   string   `json:"rule_id,omitempty"`  // deciding rule, if any
	Severity string   `json:"severity"`           // critical..info
	Reason   string   `json:"reason"`             // human-readable
	Mode     string   `json:"mode"`               // policy mode in force
	Project  string   `json:"project,omitempty"`  // TITRA_PROJECT (server grouping)
	Repo     string   `json:"repo,omitempty"`     // GITHUB_REPOSITORY
	RunID    string   `json:"run_id,omitempty"`   // GITHUB_RUN_ID or TITRA_RUN_ID
	Workflow string   `json:"workflow,omitempty"` // GITHUB_WORKFLOW
	Actor    string   `json:"actor,omitempty"`    // GITHUB_ACTOR (who triggered)
	// Source is where the action was seen: "shim" (a guarded command on PATH)
	// or an agent hook such as "claude-code" (the agent's own tool call).
	Source    string `json:"source,omitempty"`
	AgentTool string `json:"agent_tool,omitempty"` // the agent's tool name (Bash, Read, WebFetch...)
}

// NewRecord builds a Record from an attempt and its decision, stamping the CI
// context from the environment. Used for both the local log and the server
// stream so they are byte-for-byte the same shape.
func NewRecord(a engine.Attempt, d engine.Decision) Record {
	return Record{
		Time:     time.Now().UTC().Format(time.RFC3339),
		Tool:     a.Tool,
		Args:     a.Args,
		Verdict:  string(d.Verdict),
		RuleID:   d.RuleID,
		Severity: string(d.Severity),
		Reason:   d.Reason,
		Mode:     string(d.Mode),
		Project:  os.Getenv("TITRA_PROJECT"),
		Repo:     os.Getenv("GITHUB_REPOSITORY"),
		RunID:    firstNonEmpty(os.Getenv("GITHUB_RUN_ID"), os.Getenv("TITRA_RUN_ID")),
		Workflow: os.Getenv("GITHUB_WORKFLOW"),
		Actor:    os.Getenv("GITHUB_ACTOR"),
		Source:   "shim",
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Logger appends records to a file. Safe for concurrent use so parallel agent
// tool calls serialize cleanly.
type Logger struct {
	mu   sync.Mutex
	path string
}

// Open returns a Logger appending to path, creating it if needed.
func Open(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	return &Logger{path: path}, nil
}

// Log builds a record for an attempt and decision and appends it.
func (l *Logger) Log(a engine.Attempt, d engine.Decision) error {
	return l.Append(NewRecord(a, d))
}

// Append writes a prebuilt record as one JSON line.
func (l *Logger) Append(rec Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

// ReadAll loads every record from a JSONL log. Malformed lines are skipped so a
// truncated log (e.g. a killed runner) still reports what it captured.
func ReadAll(path string) ([]Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []Record
	start := 0
	for i := 0; i <= len(raw); i++ {
		if i == len(raw) || raw[i] == '\n' {
			if i > start {
				var r Record
				if json.Unmarshal(raw[start:i], &r) == nil {
					out = append(out, r)
				}
			}
			start = i + 1
		}
	}
	return out, nil
}
