package jobctx

import "strings"

// scanPermissions reads the permissions a job runs with from raw workflow
// YAML, without a full YAML parser: job-level `permissions:` wins over the
// workflow-level one. It copes with what real workflows contain and the tiny
// YAML parser doesn't: block scalars (`run: |`), comments, quoted keys and
// flow maps (`permissions: { contents: read }`).
//
// Returns the permission map (scalar forms like "read-all" become {"all":
// "read"}), where it was declared ("job" or "workflow"), and whether any
// permissions block was found.
func scanPermissions(src, job string) (map[string]string, string, bool) {
	var (
		wf, jb           map[string]string
		wfFound, jbFound bool
		top              string
		jobsIndent       = -1
		curJob           string
		jobKeyIndent     = -1
		collecting       *map[string]string
		collectIndent    = -1
		blockIndent      = -1
	)
	for _, raw := range strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n") {
		line := stripYAMLComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		ind := len(line) - len(strings.TrimLeft(line, " "))
		text := strings.TrimSpace(line)
		if blockIndent >= 0 {
			if ind > blockIndent {
				continue
			}
			blockIndent = -1
		}
		keyInd := ind
		if strings.HasPrefix(text, "- ") {
			text = strings.TrimSpace(text[2:])
			keyInd = ind + 2
		}
		key, val, isKV := cutKV(text)
		if isKV && val != "" && (val[0] == '|' || val[0] == '>') {
			blockIndent = keyInd
		}
		// Inside a permissions block: collect "scope: level" lines.
		if collecting != nil {
			if keyInd > collectIndent && isKV {
				(*collecting)[unquote(key)] = unquote(val)
				continue
			}
			collecting = nil
		}
		if ind == 0 {
			top = ""
			if isKV {
				top = unquote(key)
			}
			curJob, jobKeyIndent = "", -1
			if top == "permissions" {
				wf, wfFound = map[string]string{}, true
				if !fillInline(wf, val) {
					collecting, collectIndent = &wf, 0
				}
			}
			continue
		}
		if top != "jobs" || !isKV {
			continue
		}
		if jobsIndent < 0 {
			jobsIndent = keyInd
		}
		if keyInd == jobsIndent {
			curJob, jobKeyIndent = unquote(key), -1
			continue
		}
		if curJob != job {
			continue
		}
		if jobKeyIndent < 0 {
			jobKeyIndent = keyInd
		}
		if keyInd == jobKeyIndent && unquote(key) == "permissions" {
			jb, jbFound = map[string]string{}, true
			if !fillInline(jb, val) {
				collecting, collectIndent = &jb, keyInd
			}
		}
	}
	if jbFound {
		return jb, "job", true
	}
	if wfFound {
		return wf, "workflow", true
	}
	return nil, "", false
}

// fillInline handles `permissions: read-all`, `write-all`, `{}` and
// `{ contents: read, issues: write }`. It returns false when the value is
// empty, meaning the scopes follow on their own lines.
func fillInline(m map[string]string, val string) bool {
	val = strings.TrimSpace(val)
	switch {
	case val == "":
		return false
	case val == "read-all" || val == "write-all":
		m["all"] = strings.TrimSuffix(val, "-all")
	case strings.HasPrefix(val, "{"):
		for _, part := range strings.Split(strings.Trim(val, "{}"), ",") {
			if k, v, ok := cutKV(strings.TrimSpace(part)); ok {
				m[unquote(k)] = unquote(v)
			}
		}
	}
	return true
}

func cutKV(text string) (string, string, bool) {
	inS, inD := false, false
	for i := 0; i < len(text); i++ {
		switch text[i] {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case ':':
			if !inS && !inD && (i+1 == len(text) || text[i+1] == ' ') {
				return strings.TrimSpace(text[:i]), strings.TrimSpace(text[i+1:]), true
			}
		}
	}
	return "", "", false
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }

func stripYAMLComment(s string) string {
	inS, inD := false, false
	for i, c := range s {
		switch c {
		case '\'':
			if !inD {
				inS = !inS
			}
		case '"':
			if !inS {
				inD = !inD
			}
		case '#':
			if !inS && !inD && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t') {
				return strings.TrimRight(s[:i], " \t")
			}
		}
	}
	return s
}
