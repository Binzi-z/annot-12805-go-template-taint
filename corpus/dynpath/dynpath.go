// Package dynpath 动态模板路径落点样本。
package dynpath

import (
	"net/http"
	texttpl "text/template"

	"corpusharness/shared"
)

// 真漏洞：请求参数直接作为 ParseFiles 路径
func V14ParseFilesReq(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("tpl_path")
	texttpl.ParseFiles(p)
}

// 真漏洞：拼接构造的动态模板路径
func V15ConcatParseFiles(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := "/srv/templates/" + name + ".tpl"
	texttpl.ParseFiles(p)
}

// 真漏洞：ParseGlob 动态 glob
func V16ParseGlobReq(w http.ResponseWriter, r *http.Request) {
	g := r.URL.Query().Get("glob")
	texttpl.ParseGlob(g)
}

// 真漏洞：跨包动态模板路径
func V17CrossPkgDynPath(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Query().Get("path")
	shared.RenderName(p)
}

// decoy：filepath.Clean 后再 ParseFiles（path_clean 净化）
func D07CleanParseFiles(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	p := cleanPath("/srv/templates/" + name)
	texttpl.ParseFiles(p)
}

// decoy：白名单模板名
func D08WhitelistPath(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	safe := shared.WhitelistTpl(name)
	texttpl.ParseFiles(safe)
}
