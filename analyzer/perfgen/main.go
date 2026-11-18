// perfgen 生成大规模合成 Go 语料，用于性能基准（20 万行级）。
// 每个文件包含常量模板、请求源->模板 sink、净化 decoy、跨函数包装等混合形态。
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

const perFile = 40 // 每个文件的函数数

func main() {
	root := "perfdata"
	nFiles := 520 // 520 文件 * ~400 行 ≈ 20.8 万行
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	if len(os.Args) > 2 {
		fmt.Sscan(os.Args[2], &nFiles)
	}
	os.MkdirAll(filepath.Join(root, "mod"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "go.mod"), []byte("module perfdata\n\ngo 1.21\n"), 0o644)

	tmpl := `package mod

import (
	"net/http"
	texttpl "text/template"
)

func wrap%[1]d(s string) string { return render%[1]d(s) }
func render%[1]d(s string) string {
	t := texttpl.New("x")
	t.Parse(s)
	return s
}
func clean%[1]d(s string) string {
	if s == "" {
		return "default"
	}
	return s
}

%[2]s
`
	handler := `func H%[1]d%[2]d(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("input")
	v := wrap%[1]d(raw)
	_ = v
	t := texttpl.New("h")
	t.Parse(v)
}

func S%[1]d%[2]d(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("input")
	v := clean%[1]d(raw)
	t := texttpl.New("s")
	t.Execute(w, v)
}
`
	for fi := 0; fi < nFiles; fi++ {
		dir := filepath.Join(root, "mod", fmt.Sprintf("p%04d", fi))
		os.MkdirAll(dir, 0o755)
		var hs string
		for j := 0; j < perFile; j++ {
			hs += fmt.Sprintf(handler, fi, j)
		}
		content := fmt.Sprintf(tmpl, fi, hs)
		_ = os.WriteFile(filepath.Join(dir, "f.go"), []byte(content), 0o644)
	}
	fmt.Println("generated", nFiles, "files under", root)
}
