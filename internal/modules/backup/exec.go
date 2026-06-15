package backup

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// --- 真实数据库转储:mysqldump / pg_dump,参数数组,绝不拼 shell ---

type cmdDumper struct{}

// dump 把数据库 dbName 转储到 destFile。命令(mysqldump/pg_dump 路径)来自可配置 Settings。
// 凭证经环境变量传入(MYSQL_PWD / PGPASSWORD),不进命令行,避免出现在进程列表。
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
		bin := s.MysqlDump
		if bin == "" {
			bin = "mysqldump"
		}
		cmd = exec.Command(bin, "--single-transaction", "--databases", dbName)
	case "postgres":
		bin := s.PgDump
		if bin == "" {
			bin = "pg_dump"
		}
		cmd = exec.Command(bin, dbName)
	default:
		return 0, fmt.Errorf("unsupported db kind %q", kind)
	}
	cmd.Stdout = out
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// stderr 可能含连接信息,不外泄给客户端,仅供日志(调用方决定)。
		return 0, fmt.Errorf("dump failed: %w", err)
	}
	st, err := out.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// --- 真实 rclone CLI ---

type cmdRclone struct{}

func (cmdRclone) available() error {
	_, err := exec.LookPath("rclone")
	return err
}

// configCreate 用 `rclone config create` 写入远端。凭证作为独立参数传入(数组,不拼 shell)。
func (cmdRclone) configCreate(r Remote) error {
	args := []string{"config", "create", r.Name, r.Type}
	if r.AccessKey != "" {
		args = append(args, "access_key_id", r.AccessKey)
	}
	if r.Secret != "" {
		args = append(args, "secret_access_key", r.Secret)
	}
	if r.Endpoint != "" {
		args = append(args, "endpoint", r.Endpoint)
	}
	if r.Region != "" {
		args = append(args, "region", r.Region)
	}
	return runRclone(args...)
}

func (cmdRclone) configDelete(name string) error {
	return runRclone("config", "delete", name)
}

func (cmdRclone) upload(localFile string, r Remote) error {
	return runRclone("copy", localFile, remotePath(r))
}

func (cmdRclone) list(r Remote) ([]string, error) {
	out, err := exec.Command("rclone", "lsf", remotePath(r)).Output()
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			names = append(names, line)
		}
	}
	return names, nil
}

func (cmdRclone) download(name, localFile string, r Remote) error {
	// 取回单个对象到本地目标目录(rclone copy 复制到目录,保留文件名)。
	return runRclone("copyto", remotePath(r)+"/"+name, localFile)
}

// remotePath 拼 "name:bucket"。name 已白名单校验,bucket 由调用方信任。
func remotePath(r Remote) string {
	if r.Bucket == "" {
		return r.Name + ":"
	}
	return r.Name + ":" + r.Bucket
}

func runRclone(args ...string) error {
	cmd := exec.Command("rclone", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("rclone %s failed: %w", args[0], err)
	}
	return nil
}
