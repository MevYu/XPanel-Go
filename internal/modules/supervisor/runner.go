package supervisor

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// 默认可配置路径。GET/PUT /settings(admin)可覆盖。
const (
	defaultConfDir = "/etc/supervisor/conf.d"
	defaultLogDir  = "/var/log/supervisor"
)

// Settings 是模块的可配置项,持久化在自建表里。
type Settings struct {
	ConfDir string `json:"conf_dir"` // supervisor 程序配置目录
	LogDir  string `json:"log_dir"`  // 程序 stdout/stderr 日志目录
}

// DefaultSettings 返回内置默认值。
func DefaultSettings() Settings {
	return Settings{ConfDir: defaultConfDir, LogDir: defaultLogDir}
}

// 程序名白名单:字母数字 . _ -,长度受限。用作配置文件名与 supervisorctl 参数,
// 必须严格,挡掉路径分隔符、空格与任何注入字符。
var programNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// ValidProgramName 校验守护程序名。
func ValidProgramName(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	return programNameRe.MatchString(name)
}

// ValidCommand 校验启动命令:非空且不含换行/控制字符,避免越出 ini 行结构。
// 命令以整行写入配置文件,故重点挡行注入。
func ValidCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	return !hasCtrl(cmd)
}

// ValidDir 校验工作目录:非空、绝对路径、无换行/控制字符。
func ValidDir(dir string) bool {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return false
	}
	if !filepath.IsAbs(dir) {
		return false
	}
	return !hasCtrl(dir)
}

// ValidNumprocs 进程数须在 1..256。
func ValidNumprocs(n int) bool { return n >= 1 && n <= 256 }

func hasCtrl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r < 0x20 {
			return true
		}
	}
	return false
}

// ProgramSpec 是渲染一个 supervisor program 配置所需的全部字段。
// 调用方须保证各字段已通过对应 Valid* 校验。
type ProgramSpec struct {
	Name        string
	Command     string
	Directory   string
	AutoRestart bool
	Numprocs    int
	LogDir      string
}

// RenderConfig 用固定模板生成 supervisor [program:x] 配置。字段已校验,每个值落在
// 独立 key=value 行,危险字符已被 Valid* 挡掉,不做拼接式注入。
func RenderConfig(s ProgramSpec) string {
	autorestart := "false"
	if s.AutoRestart {
		autorestart = "true"
	}
	logDir := strings.TrimRight(strings.TrimSpace(s.LogDir), "/")
	var b strings.Builder
	fmt.Fprintf(&b, "[program:%s]\n", s.Name)
	fmt.Fprintf(&b, "command=%s\n", strings.TrimSpace(s.Command))
	fmt.Fprintf(&b, "directory=%s\n", strings.TrimSpace(s.Directory))
	fmt.Fprintf(&b, "autostart=true\n")
	fmt.Fprintf(&b, "autorestart=%s\n", autorestart)
	fmt.Fprintf(&b, "numprocs=%d\n", s.Numprocs)
	if s.Numprocs > 1 {
		// numprocs>1 时 supervisor 要求 process_name 含 %(process_num)s。
		fmt.Fprintf(&b, "process_name=%%(program_name)s_%%(process_num)02d\n")
	}
	fmt.Fprintf(&b, "stdout_logfile=%s/%s.out.log\n", logDir, s.Name)
	fmt.Fprintf(&b, "stderr_logfile=%s/%s.err.log\n", logDir, s.Name)
	return b.String()
}

// Controller 抽象对 supervisor 的所有外部副作用:写/删配置、reread+update、
// 启停查、读日志。便于用 mock 测 handler 与模板逻辑。
type Controller interface {
	// WriteConfig 把 name 的配置写到 confDir/name.conf。
	WriteConfig(confDir, name, content string) error
	// RemoveConfig 删除 confDir/name.conf(不存在视为成功)。
	RemoveConfig(confDir, name string) error
	// Reload 执行 supervisorctl reread + update,使配置变更生效。
	Reload() error
	// Action 执行 supervisorctl <verb> <name>,返回合并输出。
	Action(verb, name string) (string, error)
	// Status 返回 supervisorctl status <name> 的输出。
	Status(name string) (string, error)
	// TailLog 返回 supervisorctl tail -<lines> <name> [stderr] 的输出。
	TailLog(name string, lines int, stderr bool) (string, error)
	// Available 报告 supervisorctl 是否可用(供 HealthCheck)。
	Available() error
}

// 允许的 supervisorctl 状态变更动词。
var allowedVerbs = map[string]bool{"start": true, "stop": true, "restart": true}

// execController 是基于 supervisorctl 的真实实现。
type execController struct{}

// NewController 返回基于 supervisorctl 的真实 Controller。
func NewController() Controller { return execController{} }

func (execController) WriteConfig(confDir, name, content string) error {
	path, err := safeConfPath(confDir, name)
	if err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0o644)
}

func (execController) RemoveConfig(confDir, name string) error {
	path, err := safeConfPath(confDir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (execController) Reload() error {
	if out, err := exec.Command("supervisorctl", "reread").CombinedOutput(); err != nil {
		return fmt.Errorf("supervisorctl reread: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("supervisorctl", "update").CombinedOutput(); err != nil {
		return fmt.Errorf("supervisorctl update: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execController) Action(verb, name string) (string, error) {
	if !allowedVerbs[verb] {
		return "", fmt.Errorf("supervisor: verb %q not allowed", verb)
	}
	if !ValidProgramName(name) {
		return "", fmt.Errorf("supervisor: invalid program name %q", name)
	}
	out, err := exec.Command("supervisorctl", verb, name).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("supervisorctl %s %s: %w", verb, name, err)
	}
	return text, nil
}

func (execController) Status(name string) (string, error) {
	if !ValidProgramName(name) {
		return "", fmt.Errorf("supervisor: invalid program name %q", name)
	}
	// status 退出码非 0 属正常(程序停止),不当错误抛。
	out, _ := exec.Command("supervisorctl", "status", name).CombinedOutput()
	return strings.TrimSpace(string(out)), nil
}

func (execController) TailLog(name string, lines int, stderr bool) (string, error) {
	if !ValidProgramName(name) {
		return "", fmt.Errorf("supervisor: invalid program name %q", name)
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

func (execController) Available() error {
	_, err := exec.LookPath("supervisorctl")
	return err
}

// safeConfPath 把 confDir/name.conf 限定在 confDir 内。name 须先过白名单校验
// (无路径分隔符),这里再做一层词法兜底,确保不逃逸目录。
func safeConfPath(confDir, name string) (string, error) {
	if !ValidProgramName(name) {
		return "", fmt.Errorf("supervisor: invalid program name %q", name)
	}
	confDir = filepath.Clean(confDir)
	path := filepath.Join(confDir, name+".conf")
	if filepath.Dir(path) != confDir {
		return "", fmt.Errorf("supervisor: config path %q escapes %q", path, confDir)
	}
	return path, nil
}
