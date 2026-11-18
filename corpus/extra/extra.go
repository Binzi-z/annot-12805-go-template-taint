// Package extra 补足样本规模与额外传播形态。
package extra

import (
	"net/http"
	"strings"
	texttpl "text/template"
)

// 真漏洞（第 50 条样本）：strings.Join 传播 + 动态模板，落点为 Parse。
func V35JoinIntoTemplate(w http.ResponseWriter, r *http.Request) {
	parts := []string{"header", r.URL.Query().Get("tpl"), "footer"}
	src := strings.Join(parts, "\n")
	t := texttpl.New("v35")
	t.Parse(src)
}
