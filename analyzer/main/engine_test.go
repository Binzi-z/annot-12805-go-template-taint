package main

import (
	"os"
	"path/filepath"
	"testing"
)

// testdata 布局在每个子目录下放一个最小 Go module 片段。
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const testRules = `{
  "version": 1,
  "sources": [
    {"id": "req_query", "chain": ["URL", "Query", "Get"], "origin": "request_param"},
    {"id": "db_scan", "method": "Scan", "origin": "ops_config_db", "requiresConfigQuery": true}
  ],
  "db_config": {"tables": ["ops_template"], "taint_on_dynamic_query": false},
  "sinks": [
    {"id": "tpl_parse", "pkg": "text/template", "name": "Parse", "args": [0], "accept": ["tpl_whitelist"]},
    {"id": "tpl_files", "name": "ParseFiles", "args": [0], "accept": ["tpl_whitelist"]}
  ],
  "sanitizers": [
    {"id": "tpl_whitelist", "names": ["isAllowedTpl", "WhitelistTpl"]}
  ],
  "propagators": [
    {"name": "append", "mode": "slice_append"}, {"ident": "string"}, {"pkg": "fmt", "name": "Sprintf"}
  ],
  "config": {"max_worklist_rounds": 8, "reflect_dynamic_overapprox": true}
}`

func runAnalyze(t *testing.T, files map[string]string) []*Finding {
	t.Helper()
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "go.mod"), "module sample\n\ngo 1.21\n")
	rulePath := filepath.Join(root, "rules.json")
	writeFile(t, rulePath, testRules)
	for rel, content := range files {
		writeFile(t, filepath.Join(root, filepath.FromSlash(rel)), content)
	}
	pkgs, err := LoadPackages(root)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	prog := BuildProgram(pkgs, root)
	rules, err := LoadRules(rulePath)
	if err != nil {
		t.Fatalf("rules: %v", err)
	}
	return NewEngine(prog, rules).Run()
}

func TestDirectTaintToSink(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a
import ("net/http"; texttpl "text/template")
func H(w http.ResponseWriter, r *http.Request) {
	body := r.URL.Query().Get("tpl")
	t := texttpl.New("x")
	t.Parse(body)
}`,
	}
	got := runAnalyze(t, files)
	if len(got) != 1 || got[0].RuleID != "tpl_parse" {
		t.Fatalf("want 1 tpl_parse finding, got %+v", got)
	}
}

func TestSanitizerSuppresses(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a
import ("net/http"; texttpl "text/template")
func isAllowedTpl(s string) bool { return true }
func H(w http.ResponseWriter, r *http.Request) {
	body := r.URL.Query().Get("tpl")
	if isAllowedTpl(body) {
		t := texttpl.New("x")
		t.Parse(body)
	}
}`,
	}
	if got := runAnalyze(t, files); len(got) != 0 {
		t.Fatalf("sanitized path should not report, got %+v", got)
	}
}

func TestConstIsNotTainted(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a
import texttpl "text/template"
func H() {
	t := texttpl.New("x")
	t.Parse("static body")
}`,
	}
	if got := runAnalyze(t, files); len(got) != 0 {
		t.Fatalf("constant template must not report, got %+v", got)
	}
}

func TestCrossFunctionBubbling(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a
import ("net/http"; texttpl "text/template")
func render(s string) { t := texttpl.New("x"); t.Parse(s) }
func H(w http.ResponseWriter, r *http.Request) {
	render(r.URL.Query().Get("tpl"))
}`,
	}
	got := runAnalyze(t, files)
	if len(got) != 1 {
		t.Fatalf("want 1 finding via wrapper, got %+v", got)
	}
}

func TestConfigDBOnlyTaintsConfigTable(t *testing.T) {
	files := map[string]string{
		"a/a.go": `package a
import ("database/sql"; texttpl "text/template")
var db *sql.DB
func ConfigRows() string {
	rows, _ := db.Query("SELECT body FROM ops_template")
	defer rows.Close()
	var s string
	rows.Next()
	rows.Scan(&s)
	return s
}
func OtherRows() string {
	rows, _ := db.Query("SELECT name FROM generic_items")
	defer rows.Close()
	var s string
	rows.Next()
	rows.Scan(&s)
	return s
}
func H1() { t := texttpl.New("c"); t.Parse(ConfigRows()) }
func H2() { t := texttpl.New("g"); t.Parse(OtherRows()) }
`,
	}
	got := runAnalyze(t, files)
	if len(got) != 1 {
		t.Fatalf("only config-table Scan should taint; got %+v", got)
	}
}
