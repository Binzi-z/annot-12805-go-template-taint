package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
)

// PackageFile 一个包目录下的全部文件
type PackageFile struct {
	Dir        string
	ImportPath string
	Files      []*ast.File
	FileSet    *token.FileSet               // 每个包独立 FileSet，位置由 Position 统一取
	Imports    map[string]map[string]string // file -> alias -> importPath
}

// LoadPackages 递归扫描 root 下的 .go 文件，按目录归并为包。
// 仅使用 go/parser（语法解析库），不做类型检查、不加载依赖源码。
func LoadPackages(root string) ([]*PackageFile, error) {
	dirs := map[string][]*ast.File{}
	dirMod := map[string]string{}
	modPath := readModulePath(root)
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || strings.HasPrefix(name, ".") || name == "testdata_ignored" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") && strings.HasSuffix(path, ".go") {
			dirs[filepath.Dir(path)] = append(dirs[filepath.Dir(path)], nil)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	var pkgs []*PackageFile
	for dir := range dirs {
		fset := token.NewFileSet()
		var files []*ast.File
		imps := map[string]map[string]string{}
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			fp := filepath.Join(dir, e.Name())
			f, perr := parser.ParseFile(fset, fp, nil, parser.ParseComments|parser.AllErrors)
			if perr != nil {
				// 解析失败的文件跳过（语法错误不阻断全量分析），记录到全局错误
				parseErrors = append(parseErrors, perr.Error())
				continue
			}
			files = append(files, f)
			// 键统一为 fset 中的完整文件名，compiler 用同一名称索引
			imps[fset.Position(f.Package).Filename] = parseImports(f)
		}
		if len(files) == 0 {
			continue
		}
		rel, _ := filepath.Rel(root, dir)
		rel = filepath.ToSlash(rel)
		dirMod[dir] = rel
		pkgs = append(pkgs, &PackageFile{
			Dir:        dir,
			ImportPath: joinModulePath(modPath, rel),
			Files:      files,
			FileSet:    fset,
			Imports:    imps,
		})
	}
	return pkgs, nil
}

// readModulePath 读取分析根（或父级）go.mod 的 module 声明；不存在则返回空。
func readModulePath(root string) string {
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module"))
		}
	}
	return ""
}

func joinModulePath(mod, rel string) string {
	if mod == "" {
		return rel
	}
	if rel == "." || rel == "" {
		return mod
	}
	return mod + "/" + rel
}

var parseErrors []string

func parseImports(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, spec := range f.Imports {
		path := strings.Trim(spec.Path.Value, `"`)
		alias := filepath.Base(path)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		out[alias] = path
	}
	return out
}

// ResolveSelector 把 selector 表达式解析成 (importPath/pkg名, 方法链, 接收者表达式)。
// 例如 r.URL.Query().Get 链由调用方在 CallInfo 中处理。
func ResolveSelector(sel *ast.SelectorExpr) (receiver ast.Expr, pkgHint string, name string) {
	return sel.X, "", sel.Sel.Name
}
