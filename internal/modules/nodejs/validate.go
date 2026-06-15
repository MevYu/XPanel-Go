package nodejs

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// 严格白名单:任何未列入的输入直接拒绝,绝不拼进 supervisor 配置或 exec 参数。
// 项目名/目录/命令/端口/Node 版本全部校验,挡换行注入、路径穿越、shell 元字符。

// 项目名:字母数字开头,其后字母数字加 . _ -,长度受限。
// 用作配置文件名/进程名/目录名,必须最严。
var projectNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// Node 版本标签:如 18、18.19、18.19.0、v20,或 "system"。用作 PATH 拼接/参数,挡注入。
var nodeVersionRe = regexp.MustCompile(`^(system|v?[0-9]{1,3}(\.[0-9]{1,3}){0,2})$`)

// ValidProjectName 校验项目名(进程名/配置文件名/目录名共用)。
func ValidProjectName(name string) bool {
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return false
	}
	return projectNameRe.MatchString(name)
}

// ValidNodeVersion 校验 Node 版本标签。空串表示用默认 node,放行。
func ValidNodeVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	return nodeVersionRe.MatchString(v)
}

// ValidStartCommand 校验启动命令:非空、单行、无控制字符。
// 命令整行写入 supervisor command=,故重点挡行注入。
func ValidStartCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	return !hasCtrl(cmd)
}

// ValidPort 校验监听端口 1..65535。
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// validAbsDir 校验设置/项目目录:绝对、无控制字符与 shell 元字符、无 ..、cleaned 形式。
func validAbsDir(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("path %q must be absolute", p)
	}
	if strings.ContainsAny(p, "\n\r\t ;{}*?$`\\\"'") {
		return fmt.Errorf("path %q contains forbidden characters", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("path %q must not contain ..", p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("path %q must be in cleaned form", p)
	}
	return nil
}

// safeProjectDir 把项目目录定位到基目录下,拒绝穿越到基目录之外。
// 相对路径拼到 base 之下;绝对路径要求落在 base 内。返回 cleaned 绝对路径。
func safeProjectDir(base, dir string) (string, error) {
	base = filepath.Clean(base)
	var joined string
	if filepath.IsAbs(dir) {
		joined = filepath.Clean(dir)
	} else {
		joined = filepath.Clean(filepath.Join(base, dir))
	}
	if joined != base && !strings.HasPrefix(joined, base+string(filepath.Separator)) {
		return "", fmt.Errorf("project directory %q escapes base %q", dir, base)
	}
	if err := validAbsDir(joined); err != nil {
		return "", err
	}
	return joined, nil
}

func hasCtrl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r < 0x20 {
			return true
		}
	}
	return false
}
