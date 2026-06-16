package mysqlrepl

import (
	"context"
	"database/sql"
	"net"
	"strconv"

	"github.com/go-sql-driver/mysql"
)

// mysqlBackend 抽象一个 MySQL 实例的查询/执行,便于用 mock 测业务(测试环境无真实实例)。
type mysqlBackend interface {
	// queryRow 执行只读查询,返回首行的列名→值映射(无行返回 nil, nil)。
	// 用于 SHOW MASTER STATUS / SHOW SLAVE STATUS 这类宽行单行结果。
	queryRow(ctx context.Context, q string, args ...any) (map[string]string, error)
	// exec 执行 DDL/DCL/复制控制语句,无返回行。
	exec(ctx context.Context, q string, args ...any) error
	close() error
}

// connector 按某连接配置打开一个后端。抽成函数便于 handler 测试注入 mock。
type connector func(ctx context.Context, c connConfig) (mysqlBackend, error)

// connConfig 是建连所需的最小信息(明文密码,仅内部使用,绝不落库/进日志)。
type connConfig struct {
	Host     string
	Port     int
	User     string
	Password string
}

// sqlDBBackend 用 *sql.DB 实现 mysqlBackend。
type sqlDBBackend struct{ db *sql.DB }

func (b *sqlDBBackend) queryRow(ctx context.Context, q string, args ...any) (map[string]string, error) {
	rows, err := b.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	if !rows.Next() {
		return nil, rows.Err()
	}
	raw := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range raw {
		ptrs[i] = &raw[i]
	}
	if err := rows.Scan(ptrs...); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(cols))
	for i, name := range cols {
		out[name] = raw[i].String
	}
	return out, rows.Err()
}

func (b *sqlDBBackend) exec(ctx context.Context, q string, args ...any) error {
	_, err := b.db.ExecContext(ctx, q, args...)
	return err
}

func (b *sqlDBBackend) close() error { return b.db.Close() }

// realConnector 用给定配置建一条 MySQL 连接(host:port,无 socket:主从两端通常异机)。
func realConnector(ctx context.Context, c connConfig) (mysqlBackend, error) {
	cfg := mysql.NewConfig()
	cfg.User = c.User
	cfg.Passwd = c.Password
	cfg.Net = "tcp"
	cfg.Addr = net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
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
