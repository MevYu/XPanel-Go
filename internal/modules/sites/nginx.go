package sites

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Nginx 抽象对 nginx 的全部副作用,便于单测注入 mock。
// 实现必须保证:WriteConfig 后由调用方先 Test 通过才 Reload;Test 失败不得 Reload。
type Nginx interface {
	// WriteConfig 把 vhost 配置写到 confDir/<name>.conf(原子写)。
	WriteConfig(name, content string) error
	// RemoveConfig 删除 confDir/<name>.conf。文件不存在视为成功。
	RemoveConfig(name string) error
	// Test 执行 nginx -t,语法错误返回非 nil 且带输出。
	Test() error
	// Reload 执行 nginx -s reload。仅在 Test 通过后调用。
	Reload() error
	// Available 供 HealthCheck:nginx 是否在 PATH。
	Available() error
}

// realNginx 用 nginx CLI 实现。confDir 必须经设置校验为安全绝对目录。
type realNginx struct{ confDir string }

func newRealNginx(confDir string) *realNginx { return &realNginx{confDir: confDir} }

// confPath 计算配置文件绝对路径,二次校验 name 防穿越。
func (n *realNginx) confPath(name string) (string, error) {
	if !validSiteName(name) {
		return "", fmt.Errorf("invalid site name %q", name)
	}
	p := filepath.Join(n.confDir, name+".conf")
	if filepath.Dir(p) != filepath.Clean(n.confDir) {
		return "", fmt.Errorf("config path escapes conf dir")
	}
	return p, nil
}

func (n *realNginx) WriteConfig(name, content string) error {
	p, err := n.confPath(name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(n.confDir, 0o755); err != nil {
		return err
	}
	// 原子写:先写临时文件再 rename,避免 nginx -t 读到半写内容。
	tmp, err := os.CreateTemp(n.confDir, name+".conf.*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpName, p)
}

func (n *realNginx) RemoveConfig(name string) error {
	p, err := n.confPath(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (n *realNginx) Test() error {
	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -t failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *realNginx) Reload() error {
	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nginx -s reload failed: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (n *realNginx) Available() error {
	_, err := exec.LookPath("nginx")
	return err
}
