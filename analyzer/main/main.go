package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	var (
		target  = flag.String("target", ".", "分析目标目录（Go 源码根）")
		rulesP  = flag.String("rules", "", "规则 JSON 路径（默认 analyzer/rules/rules.json）")
		out     = flag.String("out", "findings.sarif", "SARIF 输出路径；- 表示 stdout")
		cacheP  = flag.String("cache", ".taint-cache", "增量分析缓存目录")
		incr    = flag.Bool("incremental", false, "增量模式：只分析相对上次全量发生变化的包")
		jsonOut = flag.Bool("json", false, "输出旧版 {findings:[...]} 格式（供 eval.py 兼容）")
		relBase = flag.String("rel-base", "", "结果 URI 相对基准目录（默认等于 target；评测时可传仓库根以保留 pkg/ 前缀）")
		verbose = flag.Bool("v", false, "打印统计信息到 stderr")
	)
	flag.Parse()

	root, err := filepath.Abs(*target)
	if err != nil {
		fatal(err)
	}
	uriRoot := root
	if *relBase != "" {
		if abs, e := filepath.Abs(*relBase); e == nil {
			uriRoot = abs
		}
	}
	rulesPath := *rulesP
	if rulesPath == "" {
		if exe, e := filepath.Abs(os.Args[0]); e == nil {
			rulesPath = filepath.Join(filepath.Dir(exe), "rules", "rules.json")
		}
		if _, e := os.Stat(rulesPath); e != nil {
			rulesPath = "rules/rules.json"
		}
	}
	rules, err := LoadRules(rulesPath)
	if err != nil {
		fatal(fmt.Errorf("加载规则失败: %w", err))
	}

	cache := NewCache(*cacheP)

	start := time.Now()

	// 增量模式：基于包指纹与调用依赖，只重算受影响包闭包，未变包复用缓存 findings。
	if *incr && cache.ready() {
		changed, cerr := cache.ChangedPackages(root)
		if cerr != nil {
			warn(cerr)
		}
		if len(changed) == 0 {
			// 无变化：直接回放全量缓存，零分析（满足增量 <15s 的核心场景）
			findings := cache.allFindings()
			writeOutput(findings, *jsonOut, *out, uriRoot, rulesPath, len(findings), 0)
			if *verbose {
				fmt.Fprintf(os.Stderr, "incremental: no changes, replayed %d cached findings, elapsed=%s\n",
					len(findings), time.Since(start).Round(time.Millisecond))
			}
			return
		}
		affected := cache.AffectedClosure(changed)
		allPkgs, perr := LoadPackages(root)
		if perr != nil {
			fatal(perr)
		}
		var subPkgs []*PackageFile
		for _, p := range allPkgs {
			rel, _ := filepath.Rel(root, p.Dir)
			if affected[filepath.ToSlash(rel)] {
				subPkgs = append(subPkgs, p)
			}
		}
		prog := BuildProgram(subPkgs, root)
		engine := NewEngine(prog, rules)
		fresh := engine.Run()
		// 合并：受影响包的新结果 + 未变包的缓存结果
		findings := mergeFindings(fresh, cache.CachedFindings(affected))
		// 刷新缓存：重算包的指纹/finding 覆盖，调用边与未变包保留
		cache.mergeFull(root, subPkgs, fresh, engine.Edges())
		writeOutput(findings, *jsonOut, *out, uriRoot, rulesPath, len(prog.Funcs), len(affected))
		if *verbose {
			fmt.Fprintf(os.Stderr, "incremental: changed=%d affected=%d funcs=%d findings=%d elapsed=%s\n",
				len(changed), len(affected), len(prog.Funcs), len(findings), time.Since(start).Round(time.Millisecond))
		}
		return
	}

	// 全量模式
	pkgs, err := LoadPackages(root)
	if err != nil {
		fatal(err)
	}

	prog := BuildProgram(pkgs, root)
	engine := NewEngine(prog, rules)
	findings := engine.Run()
	elapsed := time.Since(start)

	// 全量结果落盘，供后续增量复用
	if cerr := cache.SaveFull(root, pkgs, findings, engine.Edges()); cerr != nil {
		warn(cerr)
	}

	writeOutput(findings, *jsonOut, *out, uriRoot, rulesPath, len(prog.Funcs), len(pkgs))

	if *verbose {
		fmt.Fprintf(os.Stderr, "full: packages=%d funcs=%d findings=%d parse_errors=%d elapsed=%s\n",
			len(pkgs), len(prog.Funcs), len(findings), len(parseErrors), elapsed.Round(time.Millisecond))
	}
}

// writeOutput 统一输出 SARIF 或旧版 JSON。
func writeOutput(findings []*Finding, asJSON bool, out, uriRoot, rulesPath string, funcCount, pkgCount int) {
	var data []byte
	if asJSON {
		data = renderLegacyJSON(uriRoot, findings)
	} else {
		engine := &Engine{rules: mustRules(rulesPath)}
		data = renderSARIF(rulesPath, uriRoot, findings, engine, funcCount)
	}
	if out == "-" {
		os.Stdout.Write(data)
		return
	}
	if err := os.WriteFile(out, data, 0o644); err != nil {
		fatal(err)
	}
}

func mustRules(path string) *Rules {
	r, err := LoadRules(path)
	if err != nil {
		fatal(err)
	}
	return r
}

// mergeFindings 用受影响包的新 findings 替换缓存，未变包缓存保留。
func mergeFindings(fresh []*Finding, cached []CachedFinding) []*Finding {
	out := append([]*Finding{}, fresh...)
	for _, cf := range cached {
		out = append(out, &Finding{
			RuleID: cf.RuleID, File: cf.File, Line: cf.Line,
			FuncID: cf.FuncID, Origin: cf.Origin,
		})
	}
	return out
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}

func warn(err error) {
	fmt.Fprintln(os.Stderr, "warn:", err)
}
