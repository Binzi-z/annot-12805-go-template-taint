// Package macro 宏展开落点样本（可触达环境变量）。
package macro

import (
	"net/http"
	"os"

	"corpusharness/shared"
)

// 真漏洞：请求参数直接 ExpandEnv，攻击者可借 $ENV 读到环境变量
func V10ExpandEnvReq(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("expr")
	_ = os.ExpandEnv(in)
}

// 真漏洞：os.Expand 带自定义映射，请求参数可控
func V11ExpandReq(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("expr")
	_ = os.Expand(in, func(key string) string { return os.Getenv(key) })
}

// 真漏洞：跨包宏展开包装
func V12CrossPkgMacro(w http.ResponseWriter, r *http.Request) {
	in := r.Header.Get("X-Macro")
	_ = shared.ExpandMacroFile(in)
}

// 真漏洞：自定义宏展开函数（规则 macro_custom）
func V13CustomMacro(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("m")
	_ = ExpandMacro(in)
}

// ExpandMacro 项目自定义宏展开，等价 ExpandEnv。
func ExpandMacro(s string) string {
	return os.ExpandEnv(s)
}

// decoy：宏净化（剔除 $）后再展开，无法触达环境变量
func D05GuardedMacro(w http.ResponseWriter, r *http.Request) {
	in := r.URL.Query().Get("expr")
	clean := shared.SanitizeMacro(in)
	_ = os.ExpandEnv(clean)
}

// decoy：常量串展开，无污染
func D06ConstMacro(w http.ResponseWriter, r *http.Request) {
	_ = os.ExpandEnv("STATIC_PREFIX/value")
}
