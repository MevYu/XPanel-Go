package database

import (
	"context"
	"errors"
	"fmt"
	"strconv"
)

// errInvalidCharset 是字符集/排序规则/编码校验失败错误。
var errInvalidCharset = errors.New("invalid charset/collation: must match ^[A-Za-z0-9_]{1,64}$")

// bytesToMB 把字节数字符串折算为 MB(2 位小数)。非数字 → "0.00"。
func bytesToMB(s string) string {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return "0.00"
	}
	return strconv.FormatFloat(float64(n)/(1024*1024), 'f', 2, 64)
}

// atoiOr0 解析十进制整数,失败返回 0。
func atoiOr0(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}

// dialect 区分 MySQL 与 PostgreSQL 在标识符引用/列库/建用户语法上的差异。
type dialect int

const (
	dialectMySQL dialect = iota
	dialectPG
)

// quote 按方言引用一个已白名单的标识符。
func (d dialect) quote(ident string) (string, error) {
	if d == dialectPG {
		return quotePG(ident)
	}
	return quoteMySQL(ident)
}

// sqlOps 封装在某个后端上对库/用户的操作。标识符全部经白名单+引用,值尽量参数化。
type sqlOps struct {
	be sqlBackend
	d  dialect
}

// listDatabases 列出所有库名。
func (o sqlOps) listDatabases(ctx context.Context) ([]string, error) {
	if o.d == dialectPG {
		return o.be.queryStrings(ctx, `SELECT datname FROM pg_database WHERE datistemplate = false ORDER BY datname`)
	}
	return o.be.queryStrings(ctx, `SHOW DATABASES`)
}

// dbInfo 是一个库的元信息(供前端列表展示)。
type dbInfo struct {
	Name      string `json:"name"`
	SizeMB    string `json:"size_mb"`   // 数据+索引字节折算 MB(2 位小数,字符串避免精度漂移)
	Tables    int    `json:"tables"`    // 表数量
	Charset   string `json:"charset"`   // MySQL 默认字符集 / PG 编码
	Collation string `json:"collation"` // MySQL 默认排序规则 / PG collate
}

// listDatabasesInfo 列出每个库的元信息(大小 MB、表数、字符集、排序规则)。
func (o sqlOps) listDatabasesInfo(ctx context.Context) ([]dbInfo, error) {
	if o.d == dialectPG {
		return o.pgDatabasesInfo(ctx)
	}
	return o.mysqlDatabasesInfo(ctx)
}

// mysqlDatabasesInfo 从 information_schema 聚合每库大小/表数,再补默认字符集/排序规则。
func (o sqlOps) mysqlDatabasesInfo(ctx context.Context) ([]dbInfo, error) {
	rows, err := o.be.queryRows(ctx, `
		SELECT s.SCHEMA_NAME AS name,
		       s.DEFAULT_CHARACTER_SET_NAME AS charset,
		       s.DEFAULT_COLLATION_NAME AS collation,
		       COALESCE(t.tbls, 0) AS tables,
		       COALESCE(t.bytes, 0) AS bytes
		FROM information_schema.SCHEMATA s
		LEFT JOIN (
		    SELECT TABLE_SCHEMA,
		           COUNT(*) AS tbls,
		           SUM(DATA_LENGTH + INDEX_LENGTH) AS bytes
		    FROM information_schema.TABLES
		    GROUP BY TABLE_SCHEMA
		) t ON t.TABLE_SCHEMA = s.SCHEMA_NAME
		ORDER BY s.SCHEMA_NAME`)
	if err != nil {
		return nil, err
	}
	return rowsToDBInfo(rows), nil
}

// pgDatabasesInfo 用 pg_database_size 取库大小,pg_encoding_to_char 取编码;表数需逐库连接,这里置 0。
func (o sqlOps) pgDatabasesInfo(ctx context.Context) ([]dbInfo, error) {
	rows, err := o.be.queryRows(ctx, `
		SELECT d.datname AS name,
		       pg_encoding_to_char(d.encoding) AS charset,
		       d.datcollate AS collation,
		       0 AS tables,
		       pg_database_size(d.datname) AS bytes
		FROM pg_database d
		WHERE d.datistemplate = false
		ORDER BY d.datname`)
	if err != nil {
		return nil, err
	}
	return rowsToDBInfo(rows), nil
}

// rowsToDBInfo 把通用行映射转为 dbInfo,字节折算 MB。
func rowsToDBInfo(rows []map[string]string) []dbInfo {
	out := make([]dbInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, dbInfo{
			Name:      r["name"],
			SizeMB:    bytesToMB(r["bytes"]),
			Tables:    atoiOr0(r["tables"]),
			Charset:   r["charset"],
			Collation: r["collation"],
		})
	}
	return out
}

// createDatabase 建库,可选字符集/排序规则。名/字符集/排序规则均白名单。
// MySQL: CHARACTER SET / COLLATE;PG: ENCODING(字符串字面量)/ LC_COLLATE。
func (o sqlOps) createDatabase(ctx context.Context, name, charset, collation string) error {
	q, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if charset != "" && !validCharset(charset) {
		return errInvalidCharset
	}
	if collation != "" && !validCharset(collation) {
		return errInvalidCharset
	}
	if o.d == dialectPG {
		stmt := "CREATE DATABASE " + q
		if charset != "" {
			stmt += " ENCODING " + quoteStringLiteral(charset)
		}
		if collation != "" {
			stmt += " LC_COLLATE " + quoteStringLiteral(collation) + " TEMPLATE template0"
		}
		return o.be.exec(ctx, stmt)
	}
	stmt := "CREATE DATABASE " + q
	if charset != "" {
		stmt += " CHARACTER SET " + charset // 已 validCharset,非引号语境
	}
	if collation != "" {
		stmt += " COLLATE " + collation
	}
	return o.be.exec(ctx, stmt)
}

// dropDatabase 删库(危险)。
func (o sqlOps) dropDatabase(ctx context.Context, name string) error {
	q, err := o.d.quote(name)
	if err != nil {
		return err
	}
	return o.be.exec(ctx, fmt.Sprintf("DROP DATABASE %s", q))
}

// userInfo 是一个账户的信息。MySQL 区分 user@host;PG 无 host 概念(Host 为空)。
type userInfo struct {
	User string `json:"user"`
	Host string `json:"host"`
}

// listUsersInfo 列出账户(MySQL 带 host)。
func (o sqlOps) listUsersInfo(ctx context.Context) ([]userInfo, error) {
	if o.d == dialectPG {
		names, err := o.be.queryStrings(ctx, `SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname`)
		if err != nil {
			return nil, err
		}
		out := make([]userInfo, 0, len(names))
		for _, n := range names {
			out = append(out, userInfo{User: n})
		}
		return out, nil
	}
	rows, err := o.be.queryRows(ctx, `SELECT User AS user, Host AS host FROM mysql.user ORDER BY User, Host`)
	if err != nil {
		return nil, err
	}
	out := make([]userInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, userInfo{User: r["user"], Host: r["host"]})
	}
	return out, nil
}

// mysqlAccount 引用 MySQL 账户 `user`@'host'。host 经 validHost,作字符串字面量转义。
func mysqlAccount(qn, host string) string {
	return qn + "@" + quoteStringLiteral(host)
}

// createUser 建用户。MySQL 支持指定 host(localhost/%/IP);PG 无 host。口令作转义字符串字面量。
func (o sqlOps) createUser(ctx context.Context, name, password, host string) error {
	qn, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD %s", qn, quoteStringLiteral(password)))
	}
	if !validHost(host) {
		return errInvalidHost
	}
	return o.be.exec(ctx, fmt.Sprintf("CREATE USER %s IDENTIFIED BY %s", mysqlAccount(qn, host), quoteStringLiteral(password)))
}

// dropUser 删用户(危险)。MySQL 删指定 host 的账户。
func (o sqlOps) dropUser(ctx context.Context, name, host string) error {
	qn, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("DROP ROLE %s", qn))
	}
	if !validHost(host) {
		return errInvalidHost
	}
	return o.be.exec(ctx, fmt.Sprintf("DROP USER %s", mysqlAccount(qn, host)))
}

// setPassword 改用户口令。
func (o sqlOps) setPassword(ctx context.Context, name, password, host string) error {
	qn, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", qn, quoteStringLiteral(password)))
	}
	if !validHost(host) {
		return errInvalidHost
	}
	return o.be.exec(ctx, fmt.Sprintf("ALTER USER %s IDENTIFIED BY %s", mysqlAccount(qn, host), quoteStringLiteral(password)))
}

// grantAll 把某库的全部权限授予某账户(MySQL 按 host)。
func (o sqlOps) grantAll(ctx context.Context, db, user, host string) error {
	qd, err := o.d.quote(db)
	if err != nil {
		return err
	}
	qu, err := o.d.quote(user)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON DATABASE %s TO %s", qd, qu))
	}
	if !validHost(host) {
		return errInvalidHost
	}
	return o.be.exec(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s", qd, mysqlAccount(qu, host)))
}

// revokeAll 回收某库对某账户的全部权限(MySQL 按 host)。
func (o sqlOps) revokeAll(ctx context.Context, db, user, host string) error {
	qd, err := o.d.quote(db)
	if err != nil {
		return err
	}
	qu, err := o.d.quote(user)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("REVOKE ALL PRIVILEGES ON DATABASE %s FROM %s", qd, qu))
	}
	if !validHost(host) {
		return errInvalidHost
	}
	return o.be.exec(ctx, fmt.Sprintf("REVOKE ALL PRIVILEGES ON %s.* FROM %s", qd, mysqlAccount(qu, host)))
}

// quoteStringLiteral 把一个值转义为 SQL 单引号字符串字面量(用于口令等无法参数化的位置)。
// 单引号翻倍、反斜杠翻倍(MySQL 默认 NO_BACKSLASH_ESCAPES 关闭,反斜杠是转义符)。
func quoteStringLiteral(v string) string {
	out := make([]byte, 0, len(v)+2)
	out = append(out, '\'')
	for i := 0; i < len(v); i++ {
		switch v[i] {
		case '\'':
			out = append(out, '\'', '\'')
		case '\\':
			out = append(out, '\\', '\\')
		default:
			out = append(out, v[i])
		}
	}
	out = append(out, '\'')
	return string(out)
}
