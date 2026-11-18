package main

import "strings"

// rawIdent 当表达式是裸标识符时返回其名字
func (x *ExprIR) rawIdent() (string, bool) {
	if x == nil {
		return "", false
	}
	if x.Kind == EIdent {
		return x.Name, true
	}
	if x.Kind == EParen && len(x.Kids) == 1 {
		return x.Kids[0].rawIdent()
	}
	return "", false
}

// stringConst 提取表达式里的静态字符串常量（常量拼接可折叠），无法确定返回 ""
func (e *Engine) stringConst(x *ExprIR) string {
	if x == nil {
		return ""
	}
	switch x.Kind {
	case EConst:
		return strings.Trim(x.ConstVal, `"`)
	case EParen:
		return e.stringConst(x.Kids[0])
	case EBinary:
		if x.Name == "+" {
			return e.stringConst(x.Kids[0]) + e.stringConst(x.Kids[1])
		}
	}
	return ""
}

// queryReferencesConfigTable 判断查询串是否静态引用运营配置表清单
func (e *Engine) queryReferencesConfigTable(query string) bool {
	q := strings.ToLower(query)
	for _, t := range e.rules.DBConfig.Tables {
		if strings.Contains(q, strings.ToLower(t)) {
			return true
		}
	}
	return false
}

// markQueryHandle 处理 database/sql 的 Query/QueryRow：
//   - DB 句柄本身永不染污（避免“整库污染”）
//   - 仅当查询串是静态字符串且命中配置表清单时，结果 Rows 句柄才被标记为配置句柄
//   - 动态拼接 SQL 默认不标记（db_config.taint_on_dynamic_query=false）
//
// 返回该调用产生的句柄 key（是否为配置句柄已写入 configH）。
func (e *Engine) markQueryHandle(c *CallInfo) string {
	if c.BareName != "Query" && c.BareName != "QueryRow" {
		return ""
	}
	key := handleKey(c.Pos)
	if len(c.Args) == 0 {
		return key
	}
	query := e.stringConst(c.Args[0])
	if query != "" {
		if e.queryReferencesConfigTable(query) {
			e.configH[key] = true
		}
	} else if e.rules.DBConfig.TaintOnDynamicQuery {
		e.configH[key] = true
	}
	return key
}

func handleKey(p Pos) string {
	return "handle@" + p.File + ":" + itoa(p.Line)
}
