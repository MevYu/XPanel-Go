package store

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

// Store 持有 SQLite 连接。所有仓库方法挂在它上面。
type Store struct {
	DB *sql.DB
}

// Open 打开 SQLite(dsn 可为 ":memory:" 或文件路径)并运行迁移。
func Open(dsn string) (*Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// PRAGMA 只作用于执行它的那条连接;database/sql 连接池会让其它/后续
	// 连接外键仍处于关闭状态,文件 DB 下约束静默失效。限单连接后,这条
	// PRAGMA 对整个生命周期生效(也避免 :memory: 每连接独立库的隐患)。
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(`PRAGMA foreign_keys = ON`); err != nil {
		db.Close()
		return nil, err
	}
	for _, m := range migrations {
		if _, err := db.Exec(m); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &Store{DB: db}, nil
}

func (s *Store) Close() error { return s.DB.Close() }
