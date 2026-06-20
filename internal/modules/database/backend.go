package database

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"

	"github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq" // postgres 驱动:sql.Open("postgres", ...) 需此 blank import 注册
)

// sqlBackend 抽象一个 SQL 实例的连接/查询/执行,便于用 mock 测业务(测试环境无真实实例)。
type sqlBackend interface {
	// query 执行只读查询,逐行回调首列字符串。
	queryStrings(ctx context.Context, q string, args ...any) ([]string, error)
	// queryRows 执行只读查询,返回每行的列名→值映射(NULL 映射为空串)。用于带元信息的列表。
	queryRows(ctx context.Context, q string, args ...any) ([]map[string]string, error)
	// queryTable 执行任意只读查询,返回列名与每行单元格(NULL → nil)。用于数据浏览/任意 SQL。
	// maxRows>0 时最多读 maxRows 行,truncated 报告是否还有更多行未读;maxRows<=0 不限。
	queryTable(ctx context.Context, maxRows int, q string, args ...any) (cols []string, rows [][]*string, truncated bool, err error)
	// exec 执行 DDL/DCL,无返回行。
	exec(ctx context.Context, q string, args ...any) error
	// ping 测试连通。
	ping(ctx context.Context) error
	close() error
}

// dbConnector 按当前设置打开一个后端连接。抽成函数便于 handler 测试注入 mock。
type dbConnector func(ctx context.Context, s Settings) (sqlBackend, error)

// dbConnectorDB 打开一个连到指定库的后端连接。PG 连接是 per-database 的,数据浏览/任意 SQL
// 必须连到目标库;MySQL 连接无 schema 概念,dbName 仅用于 DSN dbname,查询里仍按 `db`.`tbl` 限定。
// dbName 调用前必须已过 validIdent。
type dbConnectorDB func(ctx context.Context, s Settings, dbName string) (sqlBackend, error)

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

// queryRows 扫描任意列数的结果集为字符串映射。所有列经 sql.RawBytes/[]byte 取文本,NULL → "".
func (b *sqlDBBackend) queryRows(ctx context.Context, q string, args ...any) ([]map[string]string, error) {
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]string
	for rows.Next() {
		cells := make([]sql.NullString, len(cols))
		ptrs := make([]any, len(cols))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]string, len(cols))
		for i, c := range cols {
			m[c] = cells[i].String // NullString.String 为空当 NULL
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// queryTable 通用读取:列名经 rows.Columns(),单元格按 sql.RawBytes 取文本,NULL → nil。
// maxRows>0 时读到 maxRows 即停,并多探一行判断 truncated。
func (b *sqlDBBackend) queryTable(ctx context.Context, maxRows int, q string, args ...any) ([]string, [][]*string, bool, error) {
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, nil, false, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, nil, false, err
	}
	out := make([][]*string, 0)
	truncated := false
	for rows.Next() {
		if maxRows > 0 && len(out) >= maxRows {
			truncated = true // 还有至少一行,标记截断后停止读取
			break
		}
		cells := make([]sql.RawBytes, len(cols))
		ptrs := make([]any, len(cols))
		for i := range cells {
			ptrs[i] = &cells[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, nil, false, err
		}
		row := make([]*string, len(cols))
		for i := range cells {
			if cells[i] == nil {
				row[i] = nil
				continue
			}
			s := string(cells[i]) // RawBytes 在下次 Next/Close 后失效,这里立即拷贝
			row[i] = &s
		}
		out = append(out, row)
	}
	return cols, out, truncated, rows.Err()
}

func (b *sqlDBBackend) exec(ctx context.Context, q string, args ...any) error {
	_, err := b.db.ExecContext(ctx, q, args...)
	return err
}

func (b *sqlDBBackend) ping(ctx context.Context) error { return b.db.PingContext(ctx) }
func (b *sqlDBBackend) close() error                   { return b.db.Close() }

// mysqlConnector 用设置里的 MySQL 连接信息建连(socket 优先于 host:port),不绑定具体库。
func mysqlConnector(ctx context.Context, s Settings) (sqlBackend, error) {
	return mysqlConnectorDB(ctx, s, "")
}

// mysqlConnectorDB 同 mysqlConnector,但把 dbName 设为 DSN 默认库(空则不设)。
// dbName 必须已过 validIdent。
func mysqlConnectorDB(ctx context.Context, s Settings, dbName string) (sqlBackend, error) {
	cfg := mysql.NewConfig()
	cfg.User = s.MySQLUser
	cfg.Passwd = s.MySQLPassword
	cfg.DBName = dbName
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

// pgConnector 用设置里的 PostgreSQL 连接信息建连,连到 postgres 维护库。
func pgConnector(ctx context.Context, s Settings) (sqlBackend, error) {
	return pgConnectorDB(ctx, s, "postgres")
}

// pgConnectorDB 连到指定库(PG 连接是 per-database 的)。dbName 必须已过 validIdent。
func pgConnectorDB(ctx context.Context, s Settings, dbName string) (sqlBackend, error) {
	// lib/pq DSN:键值用空格分隔,值含特殊字符时单引号包裹。这里 host/user/dbname 来自设置或已校验,
	// 密码可能含空格 → 用 quoteDSNValue 转义。dbName 已 validIdent,转义后作 dbname。
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		quoteDSNValue(s.PGHost), s.PGPort, quoteDSNValue(s.PGUser), quoteDSNValue(s.PGPassword), quoteDSNValue(dbName))
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
