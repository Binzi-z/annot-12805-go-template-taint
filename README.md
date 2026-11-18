# Go 模板注入静态分析

## 现状

`baseline/scan.py` 只做正则匹配，凡是出现 exec.Command / db.Query / os.Open / http.Get 就报。
召回够，误报高，`eval.py` 能算出具体数字。

## 语料

- `pkg/handlers.go`：14 个 handler，8 个真漏洞、6 个 decoy（同形状但过了净化）
- `main.go`：路由入口，参数来自 HTTP 查询串
- `labels.json`：真漏洞的文件、行号、sink 类别
- `eval.py`：算召回/误报

## 跑法

```
go build ./...
python baseline/scan.py > findings.json
python eval.py findings.json
```
