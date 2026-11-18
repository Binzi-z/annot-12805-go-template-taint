// genlabels 用 go/parser 为 corpus 生成基准真值标签。
// 仅用于评测样本标注：对每个 V* 函数，定位其唯一汇聚点调用所在行。
// 这是真值标注工具，不参与分析器本身。
package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var sinkNames = map[string]string{
	"Parse":          "tpl_text_parse",
	"Execute":        "tpl_execute",
	"ExecuteTemplate": "tpl_execute_tpl",
	"ParseFiles":     "tpl_parse_files",
	"ParseGlob":      "tpl_parse_glob",
	"Expand":         "macro_expand",
	"ExpandEnv":      "macro_expand_env",
	"ExpandMacro":    "macro_custom",
	"Call":           "reflect_call",
}

// wrapperSinks 跨包/接口/本地包装函数 -> 其内部汇聚点类别。
// V 函数自身无直接 sink 时，标注触发该包装调用的行。
var wrapperSinks = map[string]string{
	"RenderTpl":       "tpl_text_parse",
	"RenderName":      "tpl_parse_files",
	"Dispatch":        "tpl_text_parse",
	"Render":          "tpl_text_parse",
	"ExpandMacroFile": "macro_expand_env",
	"level1":          "tpl_text_parse",
	"consumeGlobal":   "tpl_text_parse",
}

type Label struct {
	ID    string `json:"id"`
	Sink  string `json:"sink"`
	File  string `json:"file"`
	Line  int    `json:"line"`
	Entry string `json:"entry"`
}

type Doc struct {
	Vulns []Label `json:"vulns"`
	Total int     `json:"total"`
}

func main() {
	root := "."
	if len(os.Args) > 1 {
		root = os.Args[1]
	}
	var labels []Label
	fset := token.NewFileSet()
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		if strings.Contains(path, "genlabels") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !strings.HasPrefix(fn.Name.Name, "V") {
				continue
			}
			if fn.Body == nil {
				continue
			}
			// 选 sink：按“最外层危险调用”优先，避免 htmltpl.Must(New().Parse()) 链
			// 把内部 Parse 当作主落点。先收集所有命中，再取位置最靠后的语句级调用。
			var hits []*ast.CallExpr
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				name := callName(ce)
				if _, ok := sinkNames[name]; ok {
					hits = append(hits, ce)
				}
				return true
			})
			var hit *ast.CallExpr
			var hitName string
			if len(hits) > 0 {
				// 取在源码中位置最靠后的 sink 调用（通常是真正的 render/execute 落点）
				hit = hits[len(hits)-1]
				hitName = callName(hit)
			}
			// 回退：跨包/接口/本地包装触发点
			if hit == nil {
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					if hit != nil {
						return false
					}
					ce, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					name := callName(ce)
					if _, ok := wrapperSinks[name]; ok {
						hit, hitName = ce, name
						return false
					}
					return true
				})
			}
			if hit != nil {
				pos := fset.Position(hit.Pos())
				rel, _ := filepath.Rel(root, pos.Filename)
				cat := sinkNames[hitName]
				if cat == "" {
					cat = wrapperSinks[hitName]
				}
				labels = append(labels, Label{
					ID:    fn.Name.Name,
					Sink:  cat,
					File:  filepath.ToSlash(rel),
					Line:  pos.Line,
					Entry: fn.Name.Name,
				})
			}
		}
		return nil
	})
	sort.Slice(labels, func(i, j int) bool {
		if labels[i].File != labels[j].File {
			return labels[i].File < labels[j].File
		}
		return labels[i].Line < labels[j].Line
	})
	doc := Doc{Vulns: labels, Total: len(labels)}
	out, _ := json.MarshalIndent(doc, "", "  ")
	if len(os.Args) > 2 {
		os.WriteFile(os.Args[2], out, 0o644)
	} else {
		os.Stdout.Write(out)
	}
}

func callName(ce *ast.CallExpr) string {
	switch fun := ce.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}
