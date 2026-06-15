package nodejs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ProcessManager 抽象 Node 项目的全部进程副作用:写/删配置、reload、启停查、读日志、
// 检测已装 Node 版本。便于用 mock 测 handler 与渲染逻辑,也便于切换 supervisor/systemd/pm2 后端。
//
// 默认实现 supervisorManager 走 supervisor(conf.d 配置 + supervisorctl),与本项目进程守护一致。
type ProcessManager interface {
	// Apply 把 spec 渲染成进程配置写入 confDir/<name>.conf,并 reload 使其生效。
	Apply(confDir string, spec ProcessSpec) error
	// Remove 删除 confDir/<name>.conf 并 reload(不存在视为成功)。
	Remove(confDir, name string) error
	// Action 执行 start|stop|restart,返回合并输出。
	Action(verb, name string) (string, error)
	// Status 返回进程状态文本。
	Status(name string) (string, error)
	// TailLog 返回最近 lines 行日志;stderr 为 true 取错误流。
	TailLog(name string, lines int, stderr bool) (string, error)
	// NodeVersions 返回检测到的已装 Node 版本(尽力而为,失败返回空)。
	NodeVersions() []string
	// Available 报告后端是否可用(供 HealthCheck):node 与进程管理器均在 PATH。
	Available() error
}

// ProcessSpec 是渲染一个 Node 项目进程配置所需的全部字段。
// 调用方须保证各字段已通过对应 Valid* 校验。
type ProcessSpec struct {
	Name      string
	Directory string // 项目工作目录(已校验为基目录内的绝对路径)
	Command   string // 启动命令,如 "node app.js" 或 "npm run start"
	Port      int    // 注入 PORT 环境变量
	NodePath  string // node 可执行文件所在目录;非空时前置到 PATH
	LogDir    string
}

// 允许的状态变更动词。
var allowedVerbs = map[string]bool{"start": true, "stop": true, "restart": true}

// renderConfig 用固定模板生成 supervisor [program:x] 配置。字段已校验,
// 每个值落在独立 key=value 行,危险字符已被 Valid* 挡掉,非拼接式注入。
func renderConfig(s ProcessSpec) string {
	logDir := strings.TrimRight(strings.TrimSpace(s.LogDir), "/")
	pathEnv := "%(ENV_PATH)s"
	if dir := strings.TrimSpace(s.NodePath); dir != "" {
		pathEnv = dir + ":%(ENV_PATH)s"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[program:%s]\n", s.Name)
	fmt.Fprintf(&b, "command=%s\n", strings.TrimSpace(s.Command))
	fmt.Fprintf(&b, "directory=%s\n", strings.TrimSpace(s.Directory))
	fmt.Fprintf(&b, "autostart=true\n")
	fmt.Fprintf(&b, "autorestart=true\n")
	fmt.Fprintf(&b, "environment=PORT=\"%d\",PATH=\"%s\"\n", s.Port, pathEnv)
	fmt.Fprintf(&b, "stdout_logfile=%s/%s.out.log\n", logDir, s.Name)
	fmt.Fprintf(&b, "stderr_logfile=%s/%s.err.log\n", logDir, s.Name)
	return b.String()
}

// supervisorManager 是基于 supervisorctl 的真实 ProcessManager。
type supervisorManager struct{}

// NewSupervisorManager 返回基于 supervisor 的进程管理器(默认后端)。
func NewSupervisorManager() ProcessManager { return supervisorManager{} }

func (supervisorManager) Apply(confDir string, spec ProcessSpec) error {
	path, err := safeConfPath(confDir, spec.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(path, []byte(renderConfig(spec)), 0o644); err != nil {
		return err
	}
	return reread()
}

func (supervisorManager) Remove(confDir, name string) error {
	path, err := safeConfPath(confDir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return reread()
}

func (supervisorManager) Action(verb, name string) (string, error) {
	if !allowedVerbs[verb] {
		return "", fmt.Errorf("nodejs: verb %q not allowed", verb)
	}
	if !ValidProjectName(name) {
		return "", fmt.Errorf("nodejs: invalid project name %q", name)
	}
	out, err := exec.Command("supervisorctl", verb, name).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("supervisorctl %s %s: %w", verb, name, err)
	}
	return text, nil
}

func (supervisorManager) Status(name string) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("nodejs: invalid project name %q", name)
	}
	// status 退出码非 0 属正常(进程停止),不当错误抛。
	out, _ := exec.Command("supervisorctl", "status", name).CombinedOutput()
	return strings.TrimSpace(string(out)), nil
}

func (supervisorManager) TailLog(name string, lines int, stderr bool) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("nodejs: invalid project name %q", name)
	}
	if lines <= 0 || lines > 10000 {
		lines = 200
	}
	args := []string{"tail", fmt.Sprintf("-%d", lines), name}
	if stderr {
		args = append(args, "stderr")
	}
	out, err := exec.Command("supervisorctl", args...).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("supervisorctl tail %s: %w", name, err)
	}
	return text, nil
}

func (supervisorManager) NodeVersions() []string { return detectNodeVersions() }

func (supervisorManager) Available() error {
	if _, err := exec.LookPath("node"); err != nil {
		return fmt.Errorf("node not in PATH: %w", err)
	}
	if _, err := exec.LookPath("supervisorctl"); err != nil {
		return fmt.Errorf("supervisorctl not in PATH: %w", err)
	}
	return nil
}

// reread 执行 supervisorctl reread + update,使配置变更生效。
func reread() error {
	if out, err := exec.Command("supervisorctl", "reread").CombinedOutput(); err != nil {
		return fmt.Errorf("supervisorctl reread: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("supervisorctl", "update").CombinedOutput(); err != nil {
		return fmt.Errorf("supervisorctl update: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// detectNodeVersions 尽力检测已装 Node 版本:取 PATH 中 node -v,再扫常见多版本目录。
func detectNodeVersions() []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	if b, err := exec.Command("node", "-v").Output(); err == nil {
		add(strings.TrimSpace(string(b)))
	}
	// nvm / n / fnm 等常把多版本装在版本目录下,目录名即版本号。
	for _, base := range []string{
		filepath.Join(os.Getenv("HOME"), ".nvm", "versions", "node"),
		"/usr/local/n/versions/node",
	} {
		entries, err := os.ReadDir(base)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				add(e.Name())
			}
		}
	}
	return out
}

// safeConfPath 把 confDir/name.conf 限定在 confDir 内。name 须先过白名单校验
// (无路径分隔符),这里再做一层词法兜底,确保不逃逸目录。
func safeConfPath(confDir, name string) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("nodejs: invalid project name %q", name)
	}
	confDir = filepath.Clean(confDir)
	path := filepath.Join(confDir, name+".conf")
	if filepath.Dir(path) != confDir {
		return "", fmt.Errorf("nodejs: config path %q escapes %q", path, confDir)
	}
	return path, nil
}
