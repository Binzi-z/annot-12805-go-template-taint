// Package deep 深层包装、全局传播、循环等边界样本。
package deep

import (
	"net/http"
	texttpl "text/template"
)

// 三层包装：验证效果逐层冒泡
func level3(s string) string { return render3(s) }
func render3(s string) string {
	t := texttpl.New("l3")
	t.Parse(s)
	return s
}
func level2(s string) string { return level3(s) }
func level1(s string) string { return level2(s) }

// 真漏洞：请求参数穿过三层本地函数到达 Parse
func V28ThreeLevelWrap(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("tpl")
	level1(v)
}

// 全局变量承载污点
var globalTpl string

// 真漏洞：请求参数写入包级全局，另一函数读出送 Parse
func V29GlobalCarry(w http.ResponseWriter, r *http.Request) {
	globalTpl = r.URL.Query().Get("tpl")
	consumeGlobal()
}

func consumeGlobal() {
	t := texttpl.New("v29")
	t.Parse(globalTpl)
}

// 真漏洞：切片承载污点，range 取出后送 Parse
func V30SliceCarry(w http.ResponseWriter, r *http.Request) {
	parts := []string{r.URL.Query().Get("a"), r.URL.Query().Get("b")}
	for _, p := range parts {
		t := texttpl.New("v30")
		t.Parse(p)
	}
}

// 真漏洞：map 元素污点
func V31MapCarry(w http.ResponseWriter, r *http.Request) {
	m := map[string]string{"k": r.URL.Query().Get("v")}
	t := texttpl.New("v31")
	t.Parse(m["k"])
}

// 真漏洞：条件分支两条路径都染污（路径合并）
func V32BranchMerge(w http.ResponseWriter, r *http.Request) {
	var src string
	if r.URL.Query().Get("mode") == "1" {
		src = r.URL.Query().Get("x")
	} else {
		src = r.URL.Query().Get("y")
	}
	t := texttpl.New("v32")
	t.Parse(src)
}

// 真漏洞：字节切片 []byte 转换传播
func V33ByteConversion(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("tpl")
	b := []byte(v)
	t := texttpl.New("v33")
	t.Parse(string(b))
}

// 真漏洞：append 累积后整体送 Parse
func V34AppendCarry(w http.ResponseWriter, r *http.Request) {
	var chunks []string
	chunks = append(chunks, "head ")
	chunks = append(chunks, r.URL.Query().Get("tail"))
	combined := chunks[0] + chunks[1]
	t := texttpl.New("v34")
	t.Parse(combined)
}

// decoy：三层包装但最内层前做了白名单
func D14DeepWhitelist(w http.ResponseWriter, r *http.Request) {
	v := r.URL.Query().Get("tpl")
	safe := guarded(v)
	level1(safe)
}

func guarded(s string) string {
	if !containsDoubleBrace(s) {
		return s
	}
	return "blocked"
}

func containsDoubleBrace(s string) bool {
	for i := 0; i+2 <= len(s); i++ {
		if s[i:i+2] == "{{" {
			return true
		}
	}
	return false
}

// decoy：全局写入的是常量，consumeGlobal 不受请求影响的独立路径
const constTpl = "static"

func D15GlobalConst(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("tpl")
	local := constTpl
	t := texttpl.New("d15")
	t.Parse(local)
}
