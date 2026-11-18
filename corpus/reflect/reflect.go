// Package reflectcase 反射调用传播样本。
package reflectcase

import (
	"net/http"
	"reflect"
	texttpl "text/template"
)

// Renderer 带一个 Render 方法，供反射调用。
type Renderer struct{}

func (Renderer) Render(text string) {
	t := texttpl.New("ref")
	t.Parse(text)
}

// 真漏洞：reflect.ValueOf(...).MethodByName("Render").Call，污点穿过反射
func V20ReflectCall(w http.ResponseWriter, r *http.Request) {
	text := r.URL.Query().Get("tpl")
	rv := reflect.ValueOf(Renderer{})
	m := rv.MethodByName("Render")
	args := []reflect.Value{reflect.ValueOf(text)}
	m.Call(args)
}

// 真漏洞：反射调用，参数经一次包装函数传递
func V21ReflectCallWrapped(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("tpl")
	text := wrap(raw)
	rv := reflect.ValueOf(Renderer{})
	rv.MethodByName("Render").Call([]reflect.Value{reflect.ValueOf(text)})
}

func wrap(s string) string { return s }

// decoy：反射调用但参数为常量
func D10ReflectConst(w http.ResponseWriter, r *http.Request) {
	_ = r.URL.Query().Get("tpl")
	rv := reflect.ValueOf(Renderer{})
	rv.MethodByName("Render").Call([]reflect.Value{reflect.ValueOf("const")})
}

