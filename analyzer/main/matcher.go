package main

import (
	"strings"
)

// Match 结果
type SourceMatch struct {
	Rule  *SourceRule
	Chain []string
}

type SinkMatch struct {
	Rule *SinkRule
}

type SanMatch struct {
	Rule *SanitizerRule
}

type PropMatch struct {
	Rule *PropagatorRule
}

// Matcher 依据声明式规则对归一化 CallInfo 做匹配。
// 不内置任何具体漏洞规则，全部来自 rules.json。
type Matcher struct {
	rules *Rules
	prog  *Program
}

func NewMatcher(r *Rules, p *Program) *Matcher {
	return &Matcher{rules: r, prog: p}
}

func chainString(c *CallInfo) string {
	return strings.Join(c.Chain, ".")
}

func (m *Matcher) MatchSource(c *CallInfo, recvPkg, recvLabel string, configRows bool) *SourceMatch {
	for i := range m.rules.Sources {
		sr := &m.rules.Sources[i]
		if sr.RequiresConfigQuery {
			// 数据库 Scan 类：只有配置查询产生的句柄才成立
			if !m.bareOrPkgMatch(c, sr.Pkg, sr.Method, sr.Names) {
				continue
			}
			if !configRows {
				continue
			}
			return &SourceMatch{Rule: sr}
		}
		if len(sr.Chain) > 0 {
			if chainTailEqual(c.Chain, sr.Chain) {
				return &SourceMatch{Rule: sr}
			}
			continue
		}
		if m.bareOrPkgMatch(c, sr.Pkg, firstNonEmpty(sr.Name, sr.Method), sr.Names) {
			return &SourceMatch{Rule: sr}
		}
	}
	return nil
}

func (m *Matcher) MatchSink(c *CallInfo, recvPkg, recvLabel string) *SinkMatch {
	for i := range m.rules.Sinks {
		sr := &m.rules.Sinks[i]
		if len(sr.Names) > 0 {
			if containsStr(sr.Names, c.BareName) {
				return &SinkMatch{Rule: sr}
			}
			continue
		}
		if c.BareName != sr.Name {
			continue
		}
		if sr.Receiver != "" {
			want := strings.TrimPrefix(sr.Receiver, "*")
			want = strings.TrimPrefix(want, "template.") // *template.Template -> Template
			// 接收者类型标签或类型包命中
			if recvLabel == want || strings.HasSuffix(recvLabel, "."+want) {
				return &SinkMatch{Rule: sr}
			}
			if sr.Pkg != "" && recvPkg == sr.Pkg {
				return &SinkMatch{Rule: sr}
			}
			// 语法层无类型信息：方法调用（recv 是标识符/字段，且无包路径）按方法名保守命中，
			// 覆盖 db.Query / tpl.Execute 这类接收者类型无法静态确定的场景；
			// 误报由“必须有真实污点到达参数”这一门槛控制。
			if c.IsMethod && c.PkgPath == "" && c.BareName == sr.Name {
				return &SinkMatch{Rule: sr}
			}
			continue
		}
		if sr.Pkg != "" {
			if c.PkgPath == sr.Pkg {
				return &SinkMatch{Rule: sr}
			}
			// 方法接收者的包在语法层不可得（如 t.Parse、t.Execute）：
			// 方法调用且方法名命中即保守匹配，误报由污点门槛控制。
			if c.IsMethod && c.PkgPath == "" && c.BareName == sr.Name {
				return &SinkMatch{Rule: sr}
			}
			continue
		}
		// 只给名字的规则：裸名命中
		return &SinkMatch{Rule: sr}
	}
	return nil
}

func (m *Matcher) MatchSanitizer(c *CallInfo, recvPkg, recvLabel string) *SanMatch {
	for i := range m.rules.Sanitizers {
		sr := &m.rules.Sanitizers[i]
		if len(sr.Names) > 0 {
			if containsStr(sr.Names, c.BareName) {
				return &SanMatch{Rule: sr}
			}
			continue
		}
		if c.BareName != sr.Name {
			continue
		}
		if sr.Pkg != "" && c.PkgPath != "" && c.PkgPath != sr.Pkg {
			continue
		}
		return &SanMatch{Rule: sr}
	}
	return nil
}

func (m *Matcher) MatchPropagator(c *CallInfo) *PropMatch {
	for i := range m.rules.Propagators {
		pr := &m.rules.Propagators[i]
		if pr.Ident != "" {
			// 类型转换 string(x) / []byte(x)
			if c.BareName == pr.Ident && c.PkgPath == "" && !c.IsBuiltin {
				return &PropMatch{Rule: pr}
			}
			continue
		}
		if c.BareName != pr.Name {
			continue
		}
		if pr.Pkg != "" && c.PkgPath != "" && c.PkgPath != pr.Pkg {
			continue
		}
		return &PropMatch{Rule: pr}
	}
	return nil
}

func (m *Matcher) bareOrPkgMatch(c *CallInfo, pkg, name string, names []string) bool {
	if len(names) > 0 {
		if containsStr(names, c.BareName) {
			return true
		}
		// 支持 pkg.Func 形式的名字
		for _, n := range names {
			if strings.Contains(n, ".") && strings.HasSuffix(chainString(c), n) {
				return true
			}
		}
		return false
	}
	if c.BareName != name {
		return false
	}
	if pkg != "" && c.PkgPath != "" && c.PkgPath != pkg {
		return false
	}
	return true
}

func chainTailEqual(chain, want []string) bool {
	if len(chain) < len(want) {
		return false
	}
	for i := range want {
		if chain[len(chain)-len(want)+i] != want[i] {
			return false
		}
	}
	return true
}

func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
