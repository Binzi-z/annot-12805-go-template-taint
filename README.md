# Go 模板注入静态污点分析器

针对“运营模板配置化后被塞入函数调用、读到环境变量”的事故，构建的一层**自建 IR 的 Go 静态污点分析**。

- 只用 Go 标准库语法解析（`go/parser`、`go/token`、`go/ast`），**不做类型检查、不依赖任何现成规则集**
- 源 / 汇聚点 / 净化 / 传播规则全部声明在 `analyzer/rules/rules.json`，引擎与规则解耦
- 输出 **SARIF v2.1.0**，支持全量与增量两种模式，可直接接入 CI

## 目录

```
analyzer/            分析器（独立 Go module，纯标准库）
  main/              IR、规则匹配、worklist 污点引擎、SARIF、增量缓存、CLI
  rules/rules.json   声明式污点规则
  perfgen/           性能语料生成器（合成大规模 Go 代码）
corpus/              50 条带标签样本（35 真漏洞 + 15 净化 decoy）
  genlabels/         基于 go/parser 的真值标注工具
  corpus_labels.json 真值标签
docs/taint-modeling.md  架构与“数据库配置源如何不污染整库”的建模说明
eval_corpus.py       50 样本评测（召回/误报门槛判定）
eval.py              原始 14-handler 语料评测（保留）
pkg/、main.go        原始基线语料
baseline/scan.py     旧正则基线（保留作对照）
```

## 快速开始

```bash
# 构建
cd analyzer && go build ./...

# 全量扫描，输出 SARIF
go run ./main -target <go源码根> -rules rules/rules.json -out findings.sarif

# 兼容旧 eval.py 的 JSON 输出
go run ./main -target <根> -rules rules/rules.json -out findings.json -json
```

CLI 参数：

| 参数 | 说明 |
| --- | --- |
| `-target` | 分析目标 Go 源码根目录 |
| `-rules` | 规则 JSON 路径 |
| `-out` | 输出路径，`-` 表示 stdout |
| `-json` | 输出旧版 `{findings:[...]}` 而非 SARIF |
| `-rel-base` | 结果 URI 的相对基准（评测保留 `pkg/` 前缀时用） |
| `-incremental` | 增量模式（需配合 `-cache`） |
| `-cache` | 增量缓存目录，默认 `.taint-cache` |
| `-v` | 打印包/函数/finding 数与耗时到 stderr |

## 增量模式

```bash
# 首次：全量分析并落缓存（包指纹 + 每包 finding + 包级调用依赖）
go run ./main -target <根> -rules rules/rules.json -out f.sarif -cache .taint-cache

# 之后：无变化直接回放缓存；有变化只重算受影响包的反向依赖闭包
go run ./main -target <根> -rules rules/rules.json -out f.sarif -incremental -cache .taint-cache
```

## 评测

```bash
# 50 条样本：召回 >=85%、误报 <=15% 的门槛判定（退出码 0/1）
python -I eval_corpus.py

# 原始 14-handler 语料回归
cd analyzer && go run ./main -target ../pkg -rel-base .. -rules rules/rules.json -out /tmp/p.json -json
cd .. && python eval.py /tmp/p.json

# 分析器单元测试
cd analyzer && go test ./...
```

## 当前指标

| 项 | 结果 |
| --- | --- |
| 50 样本召回率 | 100%（35/35，门槛 ≥85%） |
| 50 样本误报率 | 0%（0/15 非漏洞，门槛 ≤15%） |
| 原始 8 漏洞语料 | 召回 100%、误报 0 |
| 20 万行全量 | 约 20 秒（门槛 <3 分钟，合成全漏洞压力语料） |
| 增量（无变化） | 约 1 秒回放；单包改动约 4 秒（门槛 <15 秒） |

> 性能数字来自 `perfgen` 生成的病态语料（每个函数都含源→sink 链，finding 密度远高于真实代码）；真实项目的 finding 与效果传播规模小得多，实际耗时更低。

## 覆盖能力

- **落点**：模板引擎 render（Parse/Execute/ExecuteTemplate）、字符串拼模板、宏展开（Expand/ExpandEnv/自定义）、动态模板路径（ParseFiles/ParseGlob），并保留 SQL/命令/路径/SSRF 等经典注入规则
- **源**：请求参数（Query/Form/PostForm/Header/JSON Body/ReadAll）、运营配置（显式访问器 + 配置表 Scan）、数据库
- **传播**：跨包、跨函数、接口分发、反射 `MethodByName().Call()`、全局变量、切片/map/Builder/Sprintf 等
- **净化**：HTML 转义、模板白名单、路径 Clean、引号剔除、数字过滤、Host 白名单、宏守卫等，支持包装与条件守卫两种形态

数据库配置源“只染配置表 Scan 目标、不染整库”的建模细节见 [`docs/taint-modeling.md`](docs/taint-modeling.md)。

## CI

`.github/workflows/ci.yml` 串联：构建 → 单元测试 → 标签一致性校验 → 50 样本门槛评测 → 原始语料回归 → SARIF 冒烟 → 增量冒烟。任一门槛不达标即失败。
