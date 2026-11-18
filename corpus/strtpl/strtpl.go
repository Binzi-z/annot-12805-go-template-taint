// Package strtpl 字符串拼模板落点样本。
package strtpl

import (
	"net/http"
	"strings"
	texttpl "text/template"

	"corpusharness/configrepo"
)

// 真漏洞：请求参数拼进模板字符串再 Parse
func V06ConcatIntoTemplate(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	src := "hello " + user + " welcome"
	t := texttpl.New("v06")
	t.Parse(src)
}

// 真漏洞：strings.Builder 累积请求数据后作为模板文本
func V07BuilderIntoTemplate(w http.ResponseWriter, r *http.Request) {
	var b strings.Builder
	b.WriteString("prefix ")
	b.WriteString(r.URL.Query().Get("x"))
	t := texttpl.New("v07")
	t.Parse(b.String())
}

// 真漏洞：配置拼模板（配置源 + 拼接传播）
func V08ConfigConcatTemplate(w http.ResponseWriter, r *http.Request) {
	cfg, _ := configrepo.LoadTemplateConfig("k")
	src := cfg + "{{end}}"
	t := texttpl.New("v08")
	t.Parse(src)
}

// 真漏洞：Sprintf 传播污点进模板
func V09SprintfTemplate(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	src := sprintfWrap("TPL(%s)", q)
	t := texttpl.New("v09")
	t.Parse(src)
}

func sprintfWrap(format, v string) string {
	return sprintfImpl(format, v)
}

func sprintfImpl(format, v string) string {
	return fmtSprintf(format, v)
}

// decoy：拼接前已做模板白名单校验
func D03WhitelistAfterConcat(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	src := "hello " + user
	if isAllowedTpl(src) {
		t := texttpl.New("d03")
		t.Parse(src)
	}
}

// decoy：常量模板，无任何污点流入
func D04ConstTemplate(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("user") // 取了源但没用到模板
	t := texttpl.New("d04")
	t.Parse("static constant template body")
}
