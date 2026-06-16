package sites

import "database/sql"

// 幂等迁移:为 sites 表补齐 aaPanel 级扩展列。不动中央 migrations.go(模块自管表)。
// 每列经 hasColumn 检查后才 ADD,可重复执行。

// siteColumns 是扩展列定义(列名 → DDL 类型/默认)。新增字段在此登记。
var siteColumns = []struct{ name, ddl string }{
	{"root_dir", "TEXT NOT NULL DEFAULT ''"},
	{"php_version", "TEXT NOT NULL DEFAULT ''"},
	{"index_docs", "TEXT NOT NULL DEFAULT '[]'"},
	{"ssl", "TEXT NOT NULL DEFAULT '{}'"},
	{"rewrite_rules", "TEXT NOT NULL DEFAULT ''"},
	{"proxy_target", "TEXT NOT NULL DEFAULT ''"},
	{"dir_protect", "TEXT NOT NULL DEFAULT '[]'"},
	{"redirects", "TEXT NOT NULL DEFAULT '[]'"},
	{"anti_leech", "TEXT NOT NULL DEFAULT '{}'"},
	{"access_log", "TEXT NOT NULL DEFAULT ''"},
	{"error_log", "TEXT NOT NULL DEFAULT ''"},
	{"custom_config", "TEXT NOT NULL DEFAULT ''"},
	{"domain_bindings", "TEXT NOT NULL DEFAULT '[]'"},
	{"proxy_config", "TEXT NOT NULL DEFAULT '{}'"},
	{"limits", "TEXT NOT NULL DEFAULT '{}'"},
}

// migrateSites 幂等补列。
func migrateSites(db *sql.DB) error {
	for _, c := range siteColumns {
		has, err := hasColumn(db, "sites", c.name)
		if err != nil {
			return err
		}
		if has {
			continue
		}
		if _, err := db.Exec("ALTER TABLE sites ADD COLUMN " + c.name + " " + c.ddl); err != nil {
			return err
		}
	}
	return nil
}

// hasColumn 查 PRAGMA table_info 判断列是否存在。
func hasColumn(db *sql.DB, table, col string) (bool, error) {
	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == col {
			return true, rows.Err()
		}
	}
	return false, rows.Err()
}
