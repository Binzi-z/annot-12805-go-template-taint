# 污点建模与设计说明

本文说明分析器的整体架构，以及需求中特别要求的一个问题：**运营配置从数据库读入时，污点源如何建模，才不会把整库标成污染。**

## 1. 总体架构

```
Go 源码
  └─ go/parser + go/token + go/ast   （唯一允许的语法解析库，不做类型检查、不加载依赖）
       └─ 自建 IR（ir.go）            函数/语句/表达式三级中间表示，含 import 解析、方法链、形参类型
            └─ 规则匹配（matcher.go）  源 / 汇聚点 / 净化 / 传播，全部声明在 rules/rules.json
                 └─ 污点引擎（engine.go + eval.go）
                      上下文不敏感、字段敏感、流不敏感的全程序 worklist 求精
                      └─ 去重后的 Finding → SARIF v2.1.0 / 旧版 JSON
```

约束遵守：**只使用 Go 标准库的语法解析能力，IR 与污点规则全部自建，不引入任何现成污点规则集或静态分析框架。** 所有“什么是源、什么是 sink、什么算净化”都在 `rules/rules.json` 中声明，引擎本身不含具体漏洞规则。

## 2. 污点事实模型

一个污点事实是 `Token{Root, Tags}`：

- `Root`：污点根，标识“从哪里来”
  - `S:<sourceID>:<file:line>`：具体源（请求参数、配置访问器、配置表 Scan）
  - `G:<全限定全局名>`：包级全局变量
  - `P:<funcID>:<形参位>`：函数形参（用于跨函数效果冒泡）
- `Tags`：净化标签集合（如 `tpl_whitelist`、`html_escape`、`digits_filter`）

对象（局部变量、形参、返回值、全局、`obj[*]` 元素、`obj.Field` 字段）持有一个 Token 集合，按并集单调增长——这是 worklist 能收敛到不动点的前提。

### 传播规则（声明式，rules.json `propagators`）

字符串拼接、`fmt.Sprintf`、`append`、`[]byte/string` 转换、`strings.Join`、`strings.Builder` 的 `WriteString/String`、`reflect.ValueOf/Call` 等都作为传播子，把入参污点并到出参/接收者。

### 净化（sanitizers）

净化不删除污点，而是给 Token 打标签。sink 规则用 `accept` 声明它认可哪些净化标签；只有当某个 Token 带有该 sink 认可的标签时才放行，否则报告。支持两种形态：

1. **包装净化**：`clean := sanitizer(raw)`，返回值带标签；
2. **条件守卫**：`if sanitizer(obj) { ...obj... }`，引擎在 then 分支给该对象的所有现存 Token 统一打标。

## 3. 跨函数、接口与反射

- **跨函数**：上下文不敏感。调用点把实参 Token 并入被调函数的形参对象；被调函数内部“形参/全局到达 sink”登记为*效果（effect）*，在调用点用实参重新实例化，报告位置落在**调用点**而不是 sink 包装函数的定义处。多层包装通过形参位效果逐层冒泡。
- **worklist 求精**：函数只在获得新污点事实时重新入队；被调函数的形参/返回值/效果变化时，经调用边反向通知调用方，直到不动点或达到轮次上限。
- **接口**：IR 记录形参声明类型与结构体字段类型。接收者类型命中接口名时，把调用保守分发到所有已加载包中的同名方法实现（含跨包）。
- **反射**：`reflect.ValueOf(x).MethodByName("Render").Call(...)` 中，IR 捕获 `MethodByName` 的字符串常量；对“先赋值给变量再 `.Call`”的写法，把方法名绑定到该变量。分发时把实参污点送入所有同名方法，并在反射 `Call` 调用点实例化其内部 sink 效果。

## 4. 数据库配置源建模（重点：为什么不会整库污染）

需求背景：运营模板存在数据库表里，运营配置是合法污点源；但数据库里还有大量非配置数据。如果把“数据库读出来的一切”都标污染，等于把整库标脏，误报会失控。建模遵循三条原则。

### 原则一：DB 句柄本身永不染污

`*sql.DB`、`*sql.Rows`、`*sql.Row` 这些**句柄对象不携带污点**。污点只可能出现在“数据从查询结果读出（Scan）并写入业务变量”的那一刻。因此 `db.Query(...)`、`db.QueryRow(...)` 的返回句柄默认干净，可以自由传递而不扩散污点。

### 原则二：只有“配置表查询”产生的句柄，其 Scan 目标才染污

引擎对每个 `Query/QueryRow` 调用做静态判定（`dbmodel.go`）：

1. 提取查询串的**静态字符串常量**（支持常量折叠：`"a" + "b"` 可折叠；含变量的动态拼接无法静态确定）。
2. 仅当该常量串命中 `db_config.tables` 清单（默认 `ops_template / ops_config / sys_config / tpl_config`）时，才给结果句柄打一个**配置句柄标记**（`configH`），这是与污点完全独立的一套标记。
3. `rows.Scan(&x)` 触发源规则时，要求接收者句柄带配置标记（`requiresConfigQuery`）；命中才把 Scan 的目标参数 `x` 染为 `ops_config_db` 源。

于是：

```go
// 命中配置表 -> rows 是配置句柄 -> Scan 目标染污
rows, _ := db.Query("SELECT tpl_body FROM ops_template")
rows.Scan(&tpl)          // tpl 染污（运营配置源）

// 非配置表 -> 句柄无配置标记 -> Scan 目标不染污
rows2, _ := db.Query("SELECT name FROM generic_items")
rows2.Scan(&name)        // name 干净，不把整库标脏
```

句柄标记通过赋值别名传播：`rows := db.Query(...)` 后，`rows` 继承该标记，后续 `rows.Scan` 才能命中。多返回值赋值（`rows, err := ...`）同样处理第 0 位句柄。

### 原则三：动态 SQL 默认 fail-closed（不染污），可控开关

当查询串是动态拼接、静态无法确定其访问的表时，默认**不**把结果当配置源（`db_config.taint_on_dynamic_query = false`）。这是一个明确的精度取舍：宁可漏报“动态 SQL 取出的配置”，也不因为无法判定而把所有动态查询结果标脏、进而污染整库。对确有需要的团队，可把开关置 `true` 改为保守染污。

### 显式配置访问器

除了表名清单，规则还支持登记**配置访问器函数**（`cfg_accessor`，如 `LoadTemplateConfig`、`configrepo.Get`）。这类函数的返回值直接作为运营配置源，语义清晰、零歧义，是比解析 SQL 字符串更可靠的建模方式，推荐项目优先用访问器封装配置读取。

### 与 `LoadUserNote` 这类“非配置读取”的关系

`configrepo.LoadUserNote` 读的是 `user_notes` 表，不在配置表清单内，其 Scan 目标不染污。语料中的 `D11`、`D12` 两个 decoy 专门固化这一行为，防止后续重构退化成“凡 Scan 必染污”。

## 5. 落点（sink）覆盖

`rules/rules.json` 覆盖需求点名的四类落点，并保留扩展位：

| 类别 | 规则 |
| --- | --- |
| 模板引擎 render | `text/template.Parse`、`html/template.Parse`、`Execute`、`ExecuteTemplate` |
| 字符串拼模板 | 拼接/Builder/Sprintf/Join 出的字符串进入 `Parse` |
| 宏展开 | `os.Expand`、`os.ExpandEnv`、自定义 `ExpandMacro/RenderMacro` |
| 动态模板路径 | `ParseFiles`、`ParseGlob` |
| 经典注入（回归基线） | SQL `Query/QueryRow`、`exec.Command`、`os.Open`、`http.Get` |

语法层无法确定方法接收者类型时（如 `t.Parse` 的 `t` 类型不可静态判定），按方法名保守命中，误报由“必须有真实污点到达参数 + 净化标签校验”两道门槛控制。

## 6. 精度取舍与已知边界

- 流不敏感：不区分条件分支是否真的可达，两支事实合并，偏向召回。
- 上下文不敏感：同一函数所有调用点的形参取并集，可能让不同调用方的污点在被调函数内合流；通过净化标签与门槛控制误报。
- 无类型检查：仅靠语法、import、形参/字段声明类型做启发式推断；标准库调用按 import 路径精确识别，项目内方法按名+接口保守分发。
- 动态 SQL、反射目标为非常量方法名、复杂泛型实例化等无法静态确定的场景采取明确的 fail-closed / 保守策略，并在规则中留开关。
