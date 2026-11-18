// Package configrepo 运营配置访问层：从数据库读取模板配置。
// 污点建模要点见 docs/taint-modeling.md：句柄不染污，仅配置表查询的 Scan 目标染污。
package configrepo

import "database/sql"

var db *sql.DB

// LoadTemplateConfig 显式登记的运营配置访问器（规则 cfg_accessor 命中即染污）。
func LoadTemplateConfig(key string) (string, error) {
	var tpl string
	row := db.QueryRow("SELECT tpl_body FROM ops_template WHERE cfg_key = '" + key + "'")
	err := row.Scan(&tpl)
	return tpl, err
}

// LoadUserNote 读非配置表：不应被当作运营配置污点源。
func LoadUserNote(uid string) (string, error) {
	var note string
	row := db.QueryRow("SELECT note FROM user_notes WHERE uid = '" + uid + "'")
	err := row.Scan(&note)
	return note, err
}

// LoadTemplateConfigRows 配置表查询，Rows.Scan 目标染污。
func LoadTemplateConfigRows() ([]string, error) {
	rows, err := db.Query("SELECT tpl_body FROM ops_template")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		out = append(out, body)
	}
	return out, nil
}

// LoadGenericRows 非配置表查询，Scan 目标不染污。
func LoadGenericRows() ([]string, error) {
	rows, err := db.Query("SELECT name FROM generic_items")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}
