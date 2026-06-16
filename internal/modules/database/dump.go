package database

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

// 导出/导入用外部工具(mysqldump/pg_dump/mysql/psql)。安全约定:
//   - 凭证经环境变量(MYSQL_PWD / PGPASSWORD)注入,绝不进 argv(避免出现在进程列表/日志)。
//   - 命令路径来自可配置 Settings,空则用默认名;非空必须过 validToolPath(纵深防御)。
//   - 库名经 validIdent 白名单后才进 argv,参数全走数组,绝不拼 shell。

// errInvalidToolPath 是工具路径校验失败错误。
var errInvalidToolPath = errors.New("invalid tool path")

// validToolPath 报告工具路径是否安全:绝对路径或纯名字,无 shell 元字符。
func validToolPath(p string) bool {
	if p == "" || strings.ContainsAny(p, " \t\n;|&$<>()`\"'*?[]{}\\") {
		return false
	}
	return true
}

// toolBin 选定要执行的工具:空则用内置默认名;非空须过校验。
func toolBin(v, def string) (string, error) {
	if v == "" {
		return def, nil
	}
	if !validToolPath(v) {
		return "", errInvalidToolPath
	}
	return v, nil
}

// dumpRunner 抽象导出/导入的外部命令执行,便于 mock(测试环境无工具/无库)。
type dumpRunner interface {
	// export 把库转储写入 w(纯 SQL,未压缩)。
	export(ctx context.Context, d dialect, db string, s Settings, w io.Writer) error
	// importSQL 从 r 读取 SQL 导入到库(危险:可覆盖目标库)。
	importSQL(ctx context.Context, d dialect, db string, s Settings, r io.Reader) error
}

// execDumpRunner 用真实外部命令实现 dumpRunner。
type execDumpRunner struct{}

func (execDumpRunner) export(ctx context.Context, d dialect, db string, s Settings, w io.Writer) error {
	if !validIdent(db) {
		return errInvalidIdent
	}
	cmd, env, err := exportCmd(ctx, d, db, s)
	if err != nil {
		return err
	}
	cmd.Env = env
	cmd.Stdout = w
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.New("export failed: " + firstLine(stderr.String()))
	}
	return nil
}

func (execDumpRunner) importSQL(ctx context.Context, d dialect, db string, s Settings, r io.Reader) error {
	if !validIdent(db) {
		return errInvalidIdent
	}
	cmd, env, err := importCmd(ctx, d, db, s)
	if err != nil {
		return err
	}
	cmd.Env = env
	cmd.Stdin = r
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return errors.New("import failed: " + firstLine(stderr.String()))
	}
	return nil
}

// exportCmd 构造导出命令与环境(凭证经 env,不进 argv)。
func exportCmd(ctx context.Context, d dialect, db string, s Settings) (*exec.Cmd, []string, error) {
	if d == dialectPG {
		bin, err := toolBin(s.PGDumpBin, "pg_dump")
		if err != nil {
			return nil, nil, err
		}
		args := []string{"-h", s.PGHost, "-p", strconv.Itoa(s.PGPort), "-U", s.PGUser, db}
		return exec.CommandContext(ctx, bin, args...), pgEnv(s), nil
	}
	bin, err := toolBin(s.MySQLDumpBin, "mysqldump")
	if err != nil {
		return nil, nil, err
	}
	args := append(mysqlConnArgs(s), "--single-transaction", "--routines", "--triggers", db)
	return exec.CommandContext(ctx, bin, args...), mysqlEnv(s), nil
}

// importCmd 构造导入命令与环境。MySQL 用 mysql CLI 指定目标库;PG 用 psql -d。
func importCmd(ctx context.Context, d dialect, db string, s Settings) (*exec.Cmd, []string, error) {
	if d == dialectPG {
		bin, err := toolBin(s.PGRestoreBin, "psql")
		if err != nil {
			return nil, nil, err
		}
		args := []string{"-h", s.PGHost, "-p", strconv.Itoa(s.PGPort), "-U", s.PGUser, "-d", db}
		return exec.CommandContext(ctx, bin, args...), pgEnv(s), nil
	}
	bin, err := toolBin(s.MySQLCLIBin, "mysql")
	if err != nil {
		return nil, nil, err
	}
	args := append(mysqlConnArgs(s), db)
	return exec.CommandContext(ctx, bin, args...), mysqlEnv(s), nil
}

// mysqlConnArgs 构造 mysql/mysqldump 的连接参数(socket 优先;不含口令)。
func mysqlConnArgs(s Settings) []string {
	if s.MySQLSocket != "" {
		return []string{"--socket=" + s.MySQLSocket, "-u", s.MySQLUser}
	}
	return []string{"-h", s.MySQLHost, "-P", strconv.Itoa(s.MySQLPort), "-u", s.MySQLUser}
}

// mysqlEnv / pgEnv 把口令经环境变量注入(不进 argv)。其余继承空环境的最小集:
// 不继承宿主完整环境,只给 PATH 以便定位默认工具名。
func mysqlEnv(s Settings) []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if s.MySQLPassword != "" {
		env = append(env, "MYSQL_PWD="+s.MySQLPassword)
	}
	return env
}

func pgEnv(s Settings) []string {
	env := []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	if s.PGPassword != "" {
		env = append(env, "PGPASSWORD="+s.PGPassword)
	}
	return env
}

// firstLine 取多行错误的首行(用于对外返回简短原因,不泄露完整 stderr)。
func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	if s == "" {
		return "command error"
	}
	return s
}
