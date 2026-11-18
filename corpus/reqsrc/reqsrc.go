// Package reqsrc 各类请求参数源样本。
package reqsrc

import (
	"net/http"
	texttpl "text/template"
)

// 真漏洞：Header 源 -> 模板 Parse
func V24HeaderToParse(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("X-Tpl")
	t := texttpl.New("v24")
	t.Parse(h)
}

// 真漏洞：PostForm 源 -> 模板 Parse
func V25PostFormToParse(w http.ResponseWriter, r *http.Request) {
	v := r.PostForm.Get("body")
	t := texttpl.New("v25")
	t.Parse(v)
}

// 真漏洞：JSON 请求体 Decode 到结构体字段 -> 模板
func V26JSONBodyToParse(w http.ResponseWriter, r *http.Request) {
	var payload struct{ Tpl string }
	dec := newJSONDecoder(r.Body)
	dec.Decode(&payload)
	t := texttpl.New("v26")
	t.Parse(payload.Tpl)
}

// 真漏洞：io.ReadAll 读请求体 -> 模板
func V27ReadAllToParse(w http.ResponseWriter, r *http.Request) {
	body := readAll(r.Body)
	t := texttpl.New("v27")
	t.Parse(string(body))
}

// decoy：Header 源经 HTML 转义后用于 Execute 数据位
func D13HeaderEscaped(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("X-Tpl")
	t := texttpl.New("d13")
	t.Execute(w, htmlEscape(h))
}
