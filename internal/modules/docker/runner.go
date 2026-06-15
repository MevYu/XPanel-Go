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

// Runner 抽象对 docker CLI 的所有外部调用,便于 mock(环境可能无 docker)。
// 每个方法以参数数组调用 docker,绝不拼接 shell。
type Runner interface {
	// Run 执行 docker <args...>,返回合并输出(失败时附带错误上下文)。
	Run(ctx context.Context, args ...string) (string, error)
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
