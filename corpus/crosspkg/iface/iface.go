// Package iface 跨包 + 接口分发样本。
package iface

import (
	"net/http"

	"corpusharness/shared"
)

// 真漏洞：请求参数经接口 Dispatch -> RealRenderer.Render -> Parse
func V18InterfaceDispatch(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("tpl")
	var renderer shared.TplRenderer = shared.RealRenderer{}
	shared.Dispatch(renderer, text)
}

// 真漏洞：接口字段持有实现，污点穿过接口边界
func V19InterfaceField(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("tpl")
	holder := struct{ R shared.TplRenderer }{R: shared.RealRenderer{}}
	holder.R.Render(text)
}

// decoy：接口分发但文本是常量
func D09InterfaceConst(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("tpl")
	var renderer shared.TplRenderer = shared.RealRenderer{}
	shared.Dispatch(renderer, "constant body")
}
