package strtpl

import "fmt"

// fmtSprintf 包装 fmt.Sprintf，验证传播子跨函数传递。
func fmtSprintf(format, v string) string {
	return fmt.Sprintf(format, v)
}

// isAllowedTpl 模板白名单净化（规则 tpl_whitelist 命中）。
func isAllowedTpl(s string) bool {
	// 简化的白名单判定：不含模板动作定界符即视为安全静态模板
	return len(s) > 0 && !contains(s, "{{")
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
