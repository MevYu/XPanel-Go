package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"

	"github.com/go-sql-driver/mysql"
)

// sqlBackend 抽象一个 SQL 实例的连接/查询/执行,便于用 mock 测业务(测试环境无真实实例)。
type sqlBackend interface {
	// query 执行只读查询,逐行回调首列字符串。
	queryStrings(ctx context.Context, q string, args ...any) ([]string, error)
	// exec 执行 DDL/DCL,无返回行。
	exec(ctx context.Context, q string, args ...any) error
	// ping 测试连通。
	ping(ctx context.Context) error
	close() error
}

// dbConnector 按当前设置打开一个后端连接。抽成函数便于 handler 测试注入 mock。
type dbConnector func(ctx context.Context, s Settings) (sqlBackend, error)

// sqlDBBackend 用 *sql.DB 实现 sqlBackend(MySQL/PG 共用)。
type sqlDBBackend struct{ db *sql.DB }

func (b *sqlDBBackend) queryStrings(ctx context.Context, q string, args ...any) ([]string, error) {
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (b *sqlDBBackend) exec(ctx context.Context, q string, args ...any) error {
	_, err := b.db.ExecContext(ctx, q, args...)
	return err
}

func (b *sqlDBBackend) ping(ctx context.Context) error { return b.db.PingContext(ctx) }
func (b *sqlDBBackend) close() error                   { return b.db.Close() }

// mysqlConnector 用设置里的 MySQL 连接信息建连(socket 优先于 host:port)。
func mysqlConnector(ctx context.Context, s Settings) (sqlBackend, error) {
	cfg := mysql.NewConfig()
	cfg.User = s.MySQLUser
	cfg.Passwd = s.MySQLPassword
	if s.MySQLSocket != "" {
		cfg.Net = "unix"
		cfg.Addr = s.MySQLSocket
	} else {
		cfg.Net = "tcp"
		cfg.Addr = net.JoinHostPort(s.MySQLHost, strconv.Itoa(s.MySQLPort))
	}
	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &sqlDBBackend{db: db}, nil
}

// pgConnector 用设置里的 PostgreSQL 连接信息建连。
func pgConnector(ctx context.Context, s Settings) (sqlBackend, error) {
	// lib/pq DSN:键值用空格分隔,值含特殊字符时单引号包裹。这里 host/user 来自设置,
	// 密码可能含空格 → 用 quoteDSNValue 转义。
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable",
		quoteDSNValue(s.PGHost), s.PGPort, quoteDSNValue(s.PGUser), quoteDSNValue(s.PGPassword))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return &sqlDBBackend{db: db}, nil
}

// quoteDSNValue 转义 lib/pq DSN 值(反斜杠与单引号转义,整体单引号包裹)。
func quoteDSNValue(v string) string {
	out := make([]byte, 0, len(v)+2)
	out = append(out, '\'')
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' || v[i] == '\'' {
			out = append(out, '\\')
		}
		out = append(out, v[i])
	}
	out = append(out, '\'')
	return string(out)
}
