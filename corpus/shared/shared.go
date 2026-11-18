// Package shared 提供跨包的包装函数、接口与配置访问器，用于验证跨包传播与接口分发。
package shared

import (
	"os"
	"text/template"
)

var DBConfigTable = "ops_template"

// RenderTpl 跨包包装：模板文本来自形参，内部 Parse。
func RenderTpl(text string) {
	t := template.New("x")
	t.Parse(text)
}

// RenderName 跨包包装：动态模板路径 ParseFiles。
func RenderName(path string) {
	template.ParseFiles(path)
}

// TplRenderer 接口：验证接口方法分发。
type TplRenderer interface {
	Render(text string)
}

type RealRenderer struct{}

func (RealRenderer) Render(text string) {
	t := template.New("r")
	t.Parse(text)
}

// Dispatch 经接口调用，静态看不到具体实现。
func Dispatch(r TplRenderer, text string) {
	r.Render(text)
}

// ExpandMacroFile 宏展开包装。
func ExpandMacroFile(s string) string {
	return os.ExpandEnv(s)
}

// SanitizeMacro 净化：剔除 $ 与反引号，宏展开安全。
func SanitizeMacro(s string) string {
	out := make([]rune, 0, len(s))
	for _, ch := range s {
		if ch != '$' && ch != '`' {
			out = append(out, ch)
		}
	}
	return string(out)
}

// WhitelistTpl 模板白名单净化：只放行固定模板。
func WhitelistTpl(name string) string {
	allowed := map[string]bool{"home.tpl": true, "order.tpl": true}
	if allowed[name] {
		return name
	}
	return "safe-default.tpl"
}
