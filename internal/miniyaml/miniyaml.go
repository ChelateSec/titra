// Package miniyaml is a tiny, dependency-free parser for the block-style YAML
// subset that Titra policy files use. It deliberately supports only what a
// policy needs: nested maps, sequences, and scalars (bare / 'single' / "double"
// quoted), plus "#" comments. Flow style, anchors, multi-line scalars, and
// other advanced YAML features are intentionally unsupported.
//
// Keeping the parser in-tree and tiny means Titra ships with zero third-party
// dependencies — a deliberate choice for a tool whose whole job is reducing the
// amount of untrusted code you have to trust in your pipeline.
package miniyaml

import (
	"fmt"
	"strconv"
	"strings"
)

// Unmarshal parses block-style YAML into map[string]any / []any / scalar values.
// Scalars decode to bool, int64, float64, nil, or string.
func Unmarshal(data []byte) (any, error) {
	lines, err := tokenize(string(data))
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, nil
	}
	p := &parser{lines: lines}
	v, err := p.parseBlock(lines[0].indent)
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.lines) {
		return nil, fmt.Errorf("miniyaml: unexpected content at line %d", p.lines[p.pos].num)
	}
	return v, nil
}

type line struct {
	num    int    // 1-based source line number, for error messages
	indent int    // leading-space count
	text   string // content with indentation and trailing comment removed
}

// tokenize strips blank lines and comments and records indentation.
func tokenize(src string) ([]line, error) {
	var out []line
	for i, raw := range strings.Split(src, "\n") {
		stripped := stripComment(raw)
		trimmed := strings.TrimRight(stripped, " \t")
		if strings.TrimSpace(trimmed) == "" {
			continue // blank or comment-only line
		}
		if strings.ContainsRune(leadingWhitespace(trimmed), '\t') {
			return nil, fmt.Errorf("miniyaml: tab indentation not supported (line %d)", i+1)
		}
		out = append(out, line{num: i + 1, indent: indentOf(trimmed), text: strings.TrimLeft(trimmed, " ")})
	}
	return out, nil
}

func leadingWhitespace(s string) string {
	return s[:len(s)-len(strings.TrimLeft(s, " \t"))]
}

func indentOf(s string) int {
	return len(s) - len(strings.TrimLeft(s, " "))
}

// stripComment removes a trailing "#..." comment, respecting quotes.
func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inDouble:
			inSingle = !inSingle
		case c == '"' && !inSingle:
			inDouble = !inDouble
		case c == '#' && !inSingle && !inDouble:
			// a '#' only starts a comment if preceded by whitespace or start of line
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

type parser struct {
	lines []line
	pos   int
}

// parseBlock parses the maximal run of lines at the given indent as either a
// mapping or a sequence, returning the composed value.
func (p *parser) parseBlock(indent int) (any, error) {
	if p.pos >= len(p.lines) {
		return nil, nil
	}
	if strings.HasPrefix(p.lines[p.pos].text, "- ") || p.lines[p.pos].text == "-" {
		return p.parseSequence(indent)
	}
	return p.parseMapping(indent)
}

func (p *parser) parseMapping(indent int) (any, error) {
	m := map[string]any{}
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("miniyaml: unexpected indent at line %d", ln.num)
		}
		key, rest, ok := splitKey(ln.text)
		if !ok {
			return nil, fmt.Errorf("miniyaml: expected 'key:' at line %d: %q", ln.num, ln.text)
		}
		p.pos++
		if rest != "" {
			val, err := parseScalar(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", ln.num, err)
			}
			m[key] = val
			continue
		}
		// nested block (deeper indent) or null
		if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
			child, err := p.parseBlock(p.lines[p.pos].indent)
			if err != nil {
				return nil, err
			}
			m[key] = child
		} else {
			m[key] = nil
		}
	}
	return m, nil
}

func (p *parser) parseSequence(indent int) (any, error) {
	var seq []any
	for p.pos < len(p.lines) {
		ln := p.lines[p.pos]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, fmt.Errorf("miniyaml: unexpected indent at line %d", ln.num)
		}
		if !strings.HasPrefix(ln.text, "- ") && ln.text != "-" {
			break
		}
		item := strings.TrimPrefix(ln.text, "-")
		item = strings.TrimLeft(item, " ")
		if item == "" {
			// "- " then nested block on following deeper lines
			p.pos++
			if p.pos < len(p.lines) && p.lines[p.pos].indent > indent {
				child, err := p.parseBlock(p.lines[p.pos].indent)
				if err != nil {
					return nil, err
				}
				seq = append(seq, child)
			} else {
				seq = append(seq, nil)
			}
			continue
		}
		// Inline content after the dash. It may be "key: val" starting a map
		// whose remaining keys sit at the column of `item`.
		if key, rest, ok := splitKey(item); ok {
			itemIndent := indent + (len(ln.text) - len(item))
			// Synthesize a mapping: reuse the current line as the first key by
			// rewriting it in place, then parse a mapping at itemIndent.
			p.lines[p.pos] = line{num: ln.num, indent: itemIndent, text: item}
			_ = key
			_ = rest
			child, err := p.parseMapping(itemIndent)
			if err != nil {
				return nil, err
			}
			seq = append(seq, child)
			continue
		}
		val, err := parseScalar(item)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", ln.num, err)
		}
		seq = append(seq, val)
		p.pos++
	}
	return seq, nil
}

// splitKey splits "key: value" or "key:" into (key, value, ok).
func splitKey(s string) (key, rest string, ok bool) {
	// find the first ": " or trailing ":"
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			if i == len(s)-1 {
				return strings.TrimSpace(s[:i]), "", true
			}
			if s[i+1] == ' ' {
				return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+2:]), true
			}
		}
	}
	return "", "", false
}

func parseScalar(s string) (any, error) {
	s = strings.TrimSpace(s)
	if len(s) >= 2 {
		if s[0] == '"' && s[len(s)-1] == '"' {
			return strconv.Unquote(s)
		}
		if s[0] == '\'' && s[len(s)-1] == '\'' {
			return strings.ReplaceAll(s[1:len(s)-1], "''", "'"), nil
		}
	}
	switch s {
	case "true", "True", "TRUE":
		return true, nil
	case "false", "False", "FALSE":
		return false, nil
	case "null", "Null", "NULL", "~", "":
		return nil, nil
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f, nil
	}
	return s, nil
}
