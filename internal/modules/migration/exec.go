package migration

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// dumper 把数据库转储为单文件(导出用)。
type dumper interface {
	dump(kind, dbName, destFile string, s Settings) (int64, error)
}

// restorer 从单文件导入数据库(导入用,危险操作:覆盖目标库)。
type restorer interface {
	restore(kind, dbName, sqlFile string, s Settings) error
}

// 凭证经环境变量传入(MYSQL_PWD / PGPASSWORD),不进命令行,避免出现在进程列表。
// 命令(mysqldump/pg_dump/mysql/psql 路径)来自可配置 Settings,参数走数组,绝不拼 shell。

type cmdDumper struct{}

func (cmdDumper) dump(kind, dbName, destFile string, s Settings) (int64, error) {
	if !validDBName(dbName) {
		return 0, fmt.Errorf("invalid database name")
	}
	out, err := os.Create(destFile)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	var cmd *exec.Cmd
	switch kind {
	case "mysql":
		bin, err := binOr(s.MysqlDump, "mysqldump")
		if err != nil {
			return 0, err
		}
		cmd = exec.Command(bin, "--single-transaction", "--databases", dbName)
	case "postgres":
		bin, err := binOr(s.PgDump, "pg_dump")
		if err != nil {
			return 0, err
		}
		cmd = exec.Command(bin, dbName)
	default:
		return 0, fmt.Errorf("unsupported db kind %q", kind)
	}
	cmd.Stdout = out
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return 0, fmt.Errorf("dump failed: %w", err)
	}
	st, err := out.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

type cmdRestorer struct{}

func (cmdRestorer) restore(kind, dbName, sqlFile string, s Settings) error {
	if !validDBName(dbName) {
		return fmt.Errorf("invalid database name")
	}
	in, err := os.Open(sqlFile)
	if err != nil {
		return err
	}
	defer in.Close()

	var cmd *exec.Cmd
	switch kind {
	case "mysql":
		// mysqldump --databases 的转储自带 USE/CREATE DATABASE,无需在命令行指定库。
		bin, err := binOr(s.MysqlCLI, "mysql")
		if err != nil {
			return err
		}
		cmd = exec.Command(bin)
	case "postgres":
		bin, err := binOr(s.PsqlCLI, "psql")
		if err != nil {
			return err
		}
		cmd = exec.Command(bin, "-d", dbName)
	default:
		return fmt.Errorf("unsupported db kind %q", kind)
	}
	cmd.Stdin = in
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("restore failed: %w", err)
	}
	return nil
}

// binOr 选定要执行的工具:空则用内置默认名。返回前再校验一次(纵深防御):
// 即便有非法值绕过保存/载入校验流入此处,也拒绝执行而非把任意路径当程序运行。
func binOr(v, def string) (string, error) {
	if v == "" {
		return def, nil
	}
	if !validToolPath(v) {
		return "", errInvalidToolPath
	}
	return v, nil
}
