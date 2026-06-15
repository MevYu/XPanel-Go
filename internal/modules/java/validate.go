package java

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// 严格白名单:任何未列入的输入直接拒绝,绝不拼进 supervisor 配置或 exec 参数。
// 项目名/构件路径/JVM 参数/端口/JDK 版本/部署类型全部校验,挡换行注入、路径穿越、shell 元字符。

// 项目名:字母数字开头,其后字母数字加 . _ -,长度受限。
// 用作配置文件名/进程名/Tomcat context 名,必须最严。
var projectNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

// JDK 版本标签:如 8、11、17、21,或 1.8、17.0.9,或 "system"。用作 PATH 拼接,挡注入。
var javaVersionRe = regexp.MustCompile(`^(system|[0-9]{1,3}(\.[0-9]{1,3}){0,2})$`)

// 部署类型:jar/war 走 java -jar 独立进程;tomcat 把 war 部署进 Tomcat webapps。
var allowedTypes = map[string]bool{"jar": true, "war": true, "tomcat": true}

// ValidProjectName 校验项目名(进程名/配置文件名/context 名共用)。
func ValidProjectName(name string) bool {
	if name == "." || name == ".." || strings.Contains(name, "..") {
		return false
	}
	return projectNameRe.MatchString(name)
}

// ValidJavaVersion 校验 JDK 版本标签。空串表示用默认 java,放行。
func ValidJavaVersion(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return true
	}
	return javaVersionRe.MatchString(v)
}

// ValidProjectType 校验部署类型。
func ValidProjectType(t string) bool { return allowedTypes[t] }

// ValidJVMArgs 校验 JVM 参数:可空、单行、无控制字符、无 shell 元字符。
// 参数会拆成 exec 参数数组(非整行拼接),这里挡行注入与元字符兜底。
func ValidJVMArgs(args string) bool {
	args = strings.TrimSpace(args)
	if args == "" {
		return true
	}
	if hasCtrl(args) {
		return false
	}
	return !strings.ContainsAny(args, ";{}*?$`\\\"'&|<>")
}

// ValidPort 校验监听端口 1..65535。
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// splitArgs 把已校验的 JVM 参数行按空白拆成参数数组,供 exec 使用(绝不拼 shell)。
func splitArgs(args string) []string { return strings.Fields(args) }

// validAbsDir 校验设置目录:绝对、无控制字符与 shell 元字符、无 ..、cleaned 形式。
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

// safeArtifactPath 把 jar/war 构件路径定位到基目录下,拒绝穿越到基目录之外。
// 相对路径拼到 base 之下;绝对路径要求落在 base 内。返回 cleaned 绝对路径。
// suffix 是要求的扩展名(".jar"/".war"),空串表示不限。
func safeArtifactPath(base, p, suffix string) (string, error) {
	base = filepath.Clean(base)
	var joined string
	if filepath.IsAbs(p) {
		joined = filepath.Clean(p)
	} else {
		joined = filepath.Clean(filepath.Join(base, p))
	}
	if joined != base && !strings.HasPrefix(joined, base+string(filepath.Separator)) {
		return "", fmt.Errorf("artifact path %q escapes base %q", p, base)
	}
	if err := validAbsFile(joined); err != nil {
		return "", err
	}
	if suffix != "" && !strings.HasSuffix(joined, suffix) {
		return "", fmt.Errorf("artifact %q must end with %s", joined, suffix)
	}
	return joined, nil
}

// validAbsFile 校验构件文件路径:绝对、无控制字符与 shell 元字符、无 ..、cleaned 形式。
func validAbsFile(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return fmt.Errorf("artifact path must not be empty")
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("artifact path %q must be absolute", p)
	}
	if strings.ContainsAny(p, "\n\r\t ;{}*?$`\\\"'") {
		return fmt.Errorf("artifact path %q contains forbidden characters", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("artifact path %q must not contain ..", p)
	}
	if filepath.Clean(p) != p {
		return fmt.Errorf("artifact path %q must be in cleaned form", p)
	}
	return nil
}

func hasCtrl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r < 0x20 {
			return true
		}
	}
	return false
}
