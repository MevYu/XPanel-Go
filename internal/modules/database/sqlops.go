package database

import (
	"context"
	"fmt"
)

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

// createDatabase 建库。库名经白名单+引用进 SQL(无法参数化)。
func (o sqlOps) createDatabase(ctx context.Context, name string) error {
	q, err := o.d.quote(name)
	if err != nil {
		return err
	}
	return o.be.exec(ctx, fmt.Sprintf("CREATE DATABASE %s", q))
}

// dropDatabase 删库(危险)。
func (o sqlOps) dropDatabase(ctx context.Context, name string) error {
	q, err := o.d.quote(name)
	if err != nil {
		return err
	}
	return o.be.exec(ctx, fmt.Sprintf("DROP DATABASE %s", q))
}

// listUsers 列出用户名。
func (o sqlOps) listUsers(ctx context.Context) ([]string, error) {
	if o.d == dialectPG {
		return o.be.queryStrings(ctx, `SELECT rolname FROM pg_roles WHERE rolcanlogin ORDER BY rolname`)
	}
	return o.be.queryStrings(ctx, `SELECT User FROM mysql.user ORDER BY User`)
}

// createUser 建用户。用户名白名单+引用;口令尽量参数化。
// MySQL 的 CREATE USER 不支持把口令作占位符参数,故 PG 用参数、MySQL 用引号字符串字面量
// (口令经 quoteStringLiteral 转义,非标识符,无注入面)。
func (o sqlOps) createUser(ctx context.Context, name, password string) error {
	qn, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		// PG: 口令作字符串字面量,用 dollar-quoting 不便,用标准引号转义。
		return o.be.exec(ctx, fmt.Sprintf("CREATE ROLE %s WITH LOGIN PASSWORD %s", qn, quoteStringLiteral(password)))
	}
	return o.be.exec(ctx, fmt.Sprintf("CREATE USER %s@'%%' IDENTIFIED BY %s", qn, quoteStringLiteral(password)))
}

// dropUser 删用户(危险)。
func (o sqlOps) dropUser(ctx context.Context, name string) error {
	qn, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("DROP ROLE %s", qn))
	}
	return o.be.exec(ctx, fmt.Sprintf("DROP USER %s@'%%'", qn))
}

// setPassword 改用户口令。
func (o sqlOps) setPassword(ctx context.Context, name, password string) error {
	qn, err := o.d.quote(name)
	if err != nil {
		return err
	}
	if o.d == dialectPG {
		return o.be.exec(ctx, fmt.Sprintf("ALTER ROLE %s WITH PASSWORD %s", qn, quoteStringLiteral(password)))
	}
	return o.be.exec(ctx, fmt.Sprintf("ALTER USER %s@'%%' IDENTIFIED BY %s", qn, quoteStringLiteral(password)))
}

// grantAll 把某库的全部权限授予某用户。库名、用户名均白名单+引用。
func (o sqlOps) grantAll(ctx context.Context, db, user string) error {
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
	return o.be.exec(ctx, fmt.Sprintf("GRANT ALL PRIVILEGES ON %s.* TO %s@'%%'", qd, qu))
}

// revokeAll 回收某库对某用户的全部权限。
func (o sqlOps) revokeAll(ctx context.Context, db, user string) error {
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
	return o.be.exec(ctx, fmt.Sprintf("REVOKE ALL PRIVILEGES ON %s.* FROM %s@'%%'", qd, qu))
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
