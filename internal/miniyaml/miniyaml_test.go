package miniyaml

import (
	"reflect"
	"testing"
)

func TestScalars(t *testing.T) {
	cases := map[string]any{
		`a: 1`:          int64(1),
		`a: 1.5`:        1.5,
		`a: true`:       true,
		`a: false`:      false,
		`a: null`:       nil,
		`a: hello`:      "hello",
		`a: "hi there"`: "hi there",
		`a: 'it''s'`:    "it's",
		`a: "^push\\b"`: `^push\b`,
	}
	for src, want := range cases {
		got, err := Unmarshal([]byte(src))
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		m := got.(map[string]any)
		if !reflect.DeepEqual(m["a"], want) {
			t.Errorf("%q: got %#v (%T), want %#v (%T)", src, m["a"], m["a"], want, want)
		}
	}
}

func TestComments(t *testing.T) {
	got, err := Unmarshal([]byte("a: 1 # trailing\n# full line\nb: \"x # not a comment\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["a"] != int64(1) {
		t.Errorf("a=%v", m["a"])
	}
	if m["b"] != "x # not a comment" {
		t.Errorf("b=%v", m["b"])
	}
}

func TestPolicyShape(t *testing.T) {
	src := `version: 1
mode: enforce
default: allow
rules:
  - id: block-push
    description: Block pushes to protected branches
    action: block
    severity: critical
    match:
      tool: git
      args_regex: "^push\\b"
  - id: block-approve
    action: block
    severity: high
    match:
      tool: gh
      args_regex: "pr review"
`
	got, err := Unmarshal([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	m := got.(map[string]any)
	if m["version"] != int64(1) || m["mode"] != "enforce" || m["default"] != "allow" {
		t.Fatalf("top-level: %#v", m)
	}
	rules, ok := m["rules"].([]any)
	if !ok || len(rules) != 2 {
		t.Fatalf("rules: %#v", m["rules"])
	}
	r0 := rules[0].(map[string]any)
	if r0["id"] != "block-push" || r0["action"] != "block" || r0["severity"] != "critical" {
		t.Errorf("rule0 scalars: %#v", r0)
	}
	match := r0["match"].(map[string]any)
	if match["tool"] != "git" || match["args_regex"] != `^push\b` {
		t.Errorf("rule0 match: %#v", match)
	}
	r1 := rules[1].(map[string]any)
	if r1["id"] != "block-approve" {
		t.Errorf("rule1: %#v", r1)
	}
}

func TestSequenceOfScalars(t *testing.T) {
	got, err := Unmarshal([]byte("items:\n  - x\n  - y\n  - z\n"))
	if err != nil {
		t.Fatal(err)
	}
	items := got.(map[string]any)["items"].([]any)
	if !reflect.DeepEqual(items, []any{"x", "y", "z"}) {
		t.Errorf("items=%#v", items)
	}
}

func TestTabRejected(t *testing.T) {
	_, err := Unmarshal([]byte("a:\n\tb: 1\n"))
	if err == nil {
		t.Error("expected tab indentation to be rejected")
	}
}

func TestEmpty(t *testing.T) {
	got, err := Unmarshal([]byte("# just a comment\n\n"))
	if err != nil || got != nil {
		t.Errorf("got %#v err %v", got, err)
	}
}
