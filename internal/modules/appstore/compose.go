package appstore

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Compose 抽象对 docker compose 的全部副作用,便于单测注入 mock。
// 所有方法以"项目名 + 项目目录"定位一个实例;项目名/目录由调用方先经白名单校验。
type Compose interface {
	// WriteProject 把渲染好的 compose.yml 原子写到 projectDir 下。
	WriteProject(projectDir, content string) error
	// Up 在 projectDir 下执行 `docker compose -p <project> up -d`。
	Up(project, projectDir string) error
	// Down 执行 `docker compose -p <project> down`;removeVolumes 为真时加 -v 删数据卷。
	Down(project, projectDir string, removeVolumes bool) error
	// Stop 执行 `docker compose -p <project> stop`。
	Stop(project, projectDir string) error
	// Start 执行 `docker compose -p <project> start`。
	Start(project, projectDir string) error
	// PS 执行 `docker compose -p <project> ps` 返回状态文本。
	PS(project, projectDir string) (string, error)
	// Logs 执行 `docker compose -p <project> logs --tail <n>` 返回日志文本。
	Logs(project, projectDir string, tail int) (string, error)
	// RemoveProjectDir 删除项目目录(卸载后清理 compose 文件)。
	RemoveProjectDir(projectDir string) error
	// Available 供 HealthCheck:docker 与 docker compose 是否可用。
	Available() error
}

// realCompose 用 docker compose CLI 实现。参数一律以数组形式传入 exec,绝不拼 shell。
type realCompose struct{}

func newRealCompose() *realCompose { return &realCompose{} }

const composeFileName = "compose.yml"

func (realCompose) WriteProject(projectDir, content string) error {
	if !filepath.IsAbs(projectDir) {
		return fmt.Errorf("project dir must be absolute")
	}
	if err := os.MkdirAll(projectDir, 0o750); err != nil {
		return err
	}
	dst := filepath.Join(projectDir, composeFileName)
	tmp, err := os.CreateTemp(projectDir, composeFileName+".*.tmp")
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
	if err := os.Chmod(tmpName, 0o640); err != nil {
		return err
	}
	return os.Rename(tmpName, dst)
}

// run 在 projectDir 下执行 docker compose 子命令,统一捕获输出。
func (realCompose) run(project, projectDir string, args ...string) (string, error) {
	full := append([]string{"compose", "-p", project, "-f", filepath.Join(projectDir, composeFileName)}, args...)
	cmd := exec.Command("docker", full...)
	cmd.Dir = projectDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("docker %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (c realCompose) Up(project, projectDir string) error {
	_, err := c.run(project, projectDir, "up", "-d")
	return err
}

func (c realCompose) Down(project, projectDir string, removeVolumes bool) error {
	args := []string{"down"}
	if removeVolumes {
		args = append(args, "-v")
	}
	_, err := c.run(project, projectDir, args...)
	return err
}

func (c realCompose) Stop(project, projectDir string) error {
	_, err := c.run(project, projectDir, "stop")
	return err
}

func (c realCompose) Start(project, projectDir string) error {
	_, err := c.run(project, projectDir, "start")
	return err
}

func (c realCompose) PS(project, projectDir string) (string, error) {
	return c.run(project, projectDir, "ps")
}

func (c realCompose) Logs(project, projectDir string, tail int) (string, error) {
	if tail <= 0 || tail > 1000 {
		tail = 200
	}
	return c.run(project, projectDir, "logs", "--tail", fmt.Sprintf("%d", tail))
}

func (realCompose) RemoveProjectDir(projectDir string) error {
	if !filepath.IsAbs(projectDir) || projectDir == "/" {
		return fmt.Errorf("refusing to remove unsafe project dir %q", projectDir)
	}
	if err := os.RemoveAll(projectDir); err != nil {
		return err
	}
	return nil
}

func (realCompose) Available() error {
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker not found in PATH: %w", err)
	}
	// `docker compose version` 确认 compose v2 插件可用。
	if out, err := exec.Command("docker", "compose", "version").CombinedOutput(); err != nil {
		return fmt.Errorf("docker compose plugin unavailable: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
