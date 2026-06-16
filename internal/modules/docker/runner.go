package docker

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// 容器/镜像/网络/卷的名称或 ID 白名单:Docker 资源名允许字母数字与 . _ - : / @(repo 路径、tag、digest)。
// 严格挡掉空格、shell 元字符、路径回溯,长度受限。用作 docker CLI 参数,绝不进 shell。
var refRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,254}$`)

// ValidRef 校验容器/镜像/网络/卷的名称或 ID。
func ValidRef(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	return refRe.MatchString(s)
}

// Compose 项目名白名单:小写字母数字 _ -,长度受限(对应 docker compose -p 约束)。
var projectRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ValidProjectName 校验 compose 项目名。
func ValidProjectName(s string) bool { return projectRe.MatchString(s) }

// 容器/网络/卷/仓库的"新名字"白名单:字母数字与 . _ -,首字符为字母数字。
var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

// validName 校验创建/重命名时的资源名(比 ValidRef 更严:不含 : / @)。
func validName(s string) bool { return nameRe.MatchString(s) }

// 内存限制白名单:正整数加可选单位 b/k/m/g(docker --memory 语法)。
var memoryRe = regexp.MustCompile(`^[1-9][0-9]{0,18}[bkmgBKMG]?$`)

// validMemory 校验 --memory 取值,空串表示不改。
func validMemory(s string) bool { return s == "" || memoryRe.MatchString(s) }

// 注册表镜像服务器白名单:host[:port][/path],字母数字与 . _ - : /。
var serverRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,254}$`)

// validServer 校验镜像仓库地址(用作 docker login 参数)。
func validServer(s string) bool {
	return s != "" && !strings.Contains(s, "..") && serverRe.MatchString(s)
}

// validCPUs 校验 --cpus 取值(正小数,如 "1.5"),空串表示不改。
func validCPUs(s string) bool {
	if s == "" {
		return true
	}
	f, err := strconv.ParseFloat(s, 64)
	return err == nil && f > 0 && f <= 4096
}

// validExecArg 校验 exec 命令的单个参数:非空、无 NUL/换行,长度受限。
// 命令以参数数组传给 docker exec,不进 shell,故无需挡 shell 元字符。
func validExecArg(s string) bool {
	if s == "" || len(s) > 4096 {
		return false
	}
	for _, c := range s {
		if c == 0 || c == '\n' || c == '\r' {
			return false
		}
	}
	return true
}

// Runner 抽象对 docker CLI 的所有外部调用,便于 mock(环境可能无 docker)。
// 每个方法以参数数组调用 docker,绝不拼接 shell。
type Runner interface {
	// Run 执行 docker <args...>,返回合并输出(失败时附带错误上下文)。
	Run(ctx context.Context, args ...string) (string, error)
	// RunInput 执行 docker <args...> 并把 stdin 喂给进程(用于 login --password-stdin,
	// 避免凭证出现在参数/进程列表里)。
	RunInput(ctx context.Context, stdin string, args ...string) (string, error)
	// Available 报告 docker daemon 是否连得上(供 HealthCheck:docker version)。
	Available() error
}

// execRunner 是基于 docker CLI 的真实实现。
type execRunner struct{}

// NewRunner 返回基于 docker CLI 的真实 Runner。
func NewRunner() Runner { return execRunner{} }

func (execRunner) Run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return text, nil
}

func (execRunner) RunInput(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, text)
	}
	return text, nil
}

func (execRunner) Available() error {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Version}}")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("docker daemon unavailable: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// composeProjectDir 把 project 解析为 composeDir/project 子目录,限定不逃逸。
// project 须先过 ValidProjectName(无路径分隔符),这里再做词法兜底。
func composeProjectDir(composeDir, project string) (string, error) {
	if !ValidProjectName(project) {
		return "", fmt.Errorf("docker: invalid compose project %q", project)
	}
	base := filepath.Clean(composeDir)
	path := filepath.Join(base, project)
	if filepath.Dir(path) != base {
		return "", fmt.Errorf("docker: compose path %q escapes %q", path, base)
	}
	return path, nil
}

// clampTail 把 --tail 行数限制在合理范围,非法值回退默认。
func clampTail(raw string) string {
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > 10000 {
		return "200"
	}
	return strconv.Itoa(n)
}
