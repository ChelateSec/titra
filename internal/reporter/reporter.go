// Package reporter streams each guarded action to a Titra server in real time,
// so the dashboard shows what an agent is doing as it happens. It is best-effort
// and bounded: a slow or missing server must never delay or break the pipeline.
//
// Configuration comes from the environment the installer sets:
//
//	TITRA_SERVER   base URL of the Titra server (e.g. https://titra.acme.dev)
//	TITRA_TOKEN    ingest token identifying the project/installation
//	TITRA_RUN_ID   groups actions into one run (GitHub run id, or a generated id)
//
// With no TITRA_SERVER set, Report is a no-op — the guard still logs locally.
package reporter

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"time"

	"github.com/ChelateSec/titra/internal/audit"
)

// Enabled reports whether a server is configured.
func Enabled() bool { return os.Getenv("TITRA_SERVER") != "" }

// Report sends one action record to the server. It blocks up to a short timeout
// (the agent's command is held only this long) and swallows every error: the
// dashboard is a convenience, never a gate on the pipeline.
func Report(rec audit.Record) {
	base := os.Getenv("TITRA_SERVER")
	if base == "" {
		return
	}
	body, err := json.Marshal(rec)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, base+"/api/actions", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := os.Getenv("TITRA_TOKEN"); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	_ = resp.Body.Close()
}
