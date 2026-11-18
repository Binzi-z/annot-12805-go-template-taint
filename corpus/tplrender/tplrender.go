// Package tplrender 模板引擎 render 落点样本。
package tplrender

import (
	htmltpl "html/template"
	"net/http"
	texttpl "text/template"

	"corpusharness/configrepo"
	"corpusharness/shared"
)

// 真漏洞：请求参数 -> text/template.Parse（原始事故形态，模板里可塞函数调用）
func V01ReqToTextParse(w http.ResponseWriter, r *http.Request) {
	body := r.URL.Query().Get("tpl")
	t := texttpl.New("v01")
	t.Parse(body)
}

// 真漏洞：请求参数 -> html/template.Execute 数据位
func V02ReqToHTMLExecute(w http.ResponseWriter, r *http.Request) {
	data := r.URL.Query().Get("name")
	t := htmltpl.Must(htmltpl.New("v02").Parse("hi"))
	t.Execute(w, data)
}

// 真漏洞：运营配置访问器 -> 跨包模板 Parse
func V03ConfigToCrossPkgParse(w http.ResponseWriter, r *http.Request) {
	tpl, _ := configrepo.LoadTemplateConfig("landing")
	shared.RenderTpl(tpl)
}

// 真漏洞：配置表 Rows.Scan -> 模板 Parse
func V04ConfigRowsToParse(w http.ResponseWriter, r *http.Request) {
	bodies, _ := configrepo.LoadTemplateConfigRows()
	for _, body := range bodies {
		t := texttpl.New("v04")
		t.Parse(body)
	}
}

// 真漏洞：FormValue 源 -> ExecuteTemplate 动态数据
func V05FormToExecuteTemplate(w http.ResponseWriter, r *http.Request) {
	v := r.FormValue("payload")
	t := htmltpl.Must(htmltpl.New("v05").Parse("x"))
	t.ExecuteTemplate(w, "main", v)
}

// ---- 净化 decoy（同形状，过了白名单/转义，不应报）----

// decoy：模板名过白名单后再 ParseFiles
func D01WhitelistedParseFiles(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	safe := shared.WhitelistTpl(name)
	texttpl.ParseFiles(safe)
}

// decoy：数据经 HTML 转义后再 Execute
func D02EscapedExecute(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("name")
	clean := htmltpl.HTMLEscapeString(raw)
	t := htmltpl.Must(htmltpl.New("d02").Parse("hi"))
	t.Execute(w, clean)
}
