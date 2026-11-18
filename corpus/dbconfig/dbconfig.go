// Package dbconfig 数据库源建模样本：验证“只染配置表 Scan 目标，不染整库”。
package dbconfig

import (
	"net/http"
	texttpl "text/template"

	"corpusharness/configrepo"
)

// 真漏洞：配置访问器结果 -> 模板 Parse
func V22AccessorToParse(w http.ResponseWriter, r *http.Request) {
	tpl, _ := configrepo.LoadTemplateConfig("k")
	t := texttpl.New("v22")
	t.Parse(tpl)
}

// 真漏洞：配置表 Rows 结果 -> 模板 Parse
func V23ConfigRowsToParse(w http.ResponseWriter, r *http.Request) {
	rows, _ := configrepo.LoadTemplateConfigRows()
	for _, body := range rows {
		t := texttpl.New("v23")
		t.Parse(body)
	}
}

// decoy：非配置表（user_notes）Scan 结果 -> 模板，不应染污
func D11NonConfigTableToParse(w http.ResponseWriter, r *http.Request) {
	note, _ := configrepo.LoadUserNote("u1")
	t := texttpl.New("d11")
	t.Parse(note)
}

// decoy：非配置表 Rows（generic_items）-> 模板，不应染污
func D12GenericRowsToParse(w http.ResponseWriter, r *http.Request) {
	names, _ := configrepo.LoadGenericRows()
	for _, n := range names {
		t := texttpl.New("d12")
		t.Parse(n)
	}
}
