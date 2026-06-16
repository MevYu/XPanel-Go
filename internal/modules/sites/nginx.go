package sites

import (
	"fmt"
	"io"
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
	// WriteHtpasswd 写 <confDir>/htpasswd/<name>.htpasswd(目录保护用)。
	WriteHtpasswd(name, content string) error
	// RemoveHtpasswd 删除站点的 .htpasswd。不存在视为成功。
	RemoveHtpasswd(name string) error
	// ReadLog 读取日志文件末尾 tail 行。path 必须是受控的绝对日志路径。
	ReadLog(path string, tail int) (string, error)
	// OpenLog 打开整个日志文件供流式下载。path 必须是受控的绝对日志路径。
	// 文件不存在返回 (nil, nil),调用方据此当作空内容处理。调用方负责 Close。
	OpenLog(path string) (io.ReadCloser, error)
	// WriteCert 把上传的证书/私钥 PEM 写到 confDir/ssl/<name>/,返回两文件绝对路径。
	WriteCert(name, certPEM, keyPEM string) (certPath, keyPath string, err error)
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
	return atomicWrite(n.confDir, p, content, 0o644)
}

func (n *realNginx) RemoveConfig(name string) error {
	p, err := n.confPath(name)
	if err != nil {
		return err
	}
	return removeIfExists(p)
}

// htpasswdPath 计算 .htpasswd 绝对路径(confDir/htpasswd/<name>.htpasswd),二次校验 name。
func (n *realNginx) htpasswdPath(name string) (string, error) {
	if !validSiteName(name) {
		return "", fmt.Errorf("invalid site name %q", name)
	}
	dir := filepath.Join(n.confDir, "htpasswd")
	p := filepath.Join(dir, name+".htpasswd")
	if filepath.Dir(p) != filepath.Clean(dir) {
		return "", fmt.Errorf("htpasswd path escapes dir")
	}
	return p, nil
}

func (n *realNginx) WriteHtpasswd(name, content string) error {
	p, err := n.htpasswdPath(name)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Dir(p), p, content, 0o640)
}

func (n *realNginx) RemoveHtpasswd(name string) error {
	p, err := n.htpasswdPath(name)
	if err != nil {
		return err
	}
	return removeIfExists(p)
}

// ReadLog 读取日志文件末尾 tail 行。文件不存在返回空串(站点尚无流量)。
func (n *realNginx) ReadLog(path string, tail int) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return lastLines(string(b), tail), nil
}

// OpenLog 打开日志文件供流式下载。不存在返回 (nil, nil)。
func (n *realNginx) OpenLog(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	return f, nil
}

func (n *realNginx) WriteCert(name, certPEM, keyPEM string) (string, string, error) {
	if !validSiteName(name) {
		return "", "", fmt.Errorf("invalid site name %q", name)
	}
	dir := filepath.Join(n.confDir, "ssl", name)
	if filepath.Dir(dir) != filepath.Clean(filepath.Join(n.confDir, "ssl")) {
		return "", "", fmt.Errorf("ssl path escapes dir")
	}
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "privkey.pem")
	if err := atomicWrite(dir, certPath, certPEM, 0o644); err != nil {
		return "", "", err
	}
	if err := atomicWrite(dir, keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// atomicWrite 原子写:先写临时文件再 rename,避免读到半写内容。
func atomicWrite(dir, dst, content string, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".*.tmp")
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
	if err := os.Chmod(tmpName, mode); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

func removeIfExists(p string) error {
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// lastLines 返回文本末尾 n 行。
func lastLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
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
