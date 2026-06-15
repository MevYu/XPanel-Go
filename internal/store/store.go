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
	// 外键约束默认关闭,显式开启
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
