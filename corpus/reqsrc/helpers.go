package reqsrc

import (
	"encoding/json"
	"html"
	"io"
)

// 以下包装让语料不直接依赖具体实例类型，同时保留调用链形态。

type decoder interface {
	Decode(v any) error
}

func newJSONDecoder(r io.Reader) decoder {
	return json.NewDecoder(r)
}

func readAll(r io.Reader) []byte {
	b, _ := io.ReadAll(r)
	return b
}

func htmlEscape(s string) string {
	return html.EscapeString(s)
}
