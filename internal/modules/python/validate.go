package python

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// 项目名白名单:字母数字 . _ -,长度受限。用作目录段名、配置文件名与 supervisor
// program 名,必须严格,挡掉路径分隔符、空格与任何注入字符。
var projectNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)

// ValidProjectName 校验 Python 项目名。
func ValidProjectName(name string) bool {
	if name == "." || name == ".." {
		return false
	}
	return projectNameRe.MatchString(name)
}

// pythonVersionRe 允许 "python3"、"python3.11"、"3.11"、"3" 形式的版本标识。
// 仅用于拼出解释器名/在 base 解释器目录下选 venv,严格挡注入。
var pythonVersionRe = regexp.MustCompile(`^(python)?3(\.\d{1,2})?$`)

// ValidPythonVersion 校验解释器版本标识(如 python3.11 / 3.11 / python3)。
func ValidPythonVersion(v string) bool {
	return pythonVersionRe.MatchString(strings.TrimSpace(v))
}

// 启动方式白名单:gunicorn / uvicorn / 直接脚本。决定如何生成进程启动命令。
const (
	StartGunicorn = "gunicorn"
	StartUvicorn  = "uvicorn"
	StartScript   = "script"
)

var allowedStartKinds = map[string]bool{
	StartGunicorn: true, StartUvicorn: true, StartScript: true,
}

// ValidStartKind 校验启动方式。
func ValidStartKind(k string) bool { return allowedStartKinds[k] }

// ValidPort 校验监听端口:1..65535。
func ValidPort(p int) bool { return p >= 1 && p <= 65535 }

// appModuleRe 校验 WSGI/ASGI 入口("module:app" 形式)或纯脚本相对路径。
// 仅允许字母数字 . _ - / :,挡掉空格与 shell 元字符,避免命令注入。
var appModuleRe = regexp.MustCompile(`^[a-zA-Z0-9._/:-]{1,128}$`)

// ValidAppTarget 校验入口标识:gunicorn/uvicorn 的 "module:app" 或脚本路径。
// 不得为绝对路径(在项目目录内相对解析),不得含 .. 段。
func ValidAppTarget(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" || !appModuleRe.MatchString(t) {
		return false
	}
	if filepath.IsAbs(t) {
		return false
	}
	for _, seg := range strings.Split(t, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// ValidDir 校验目录:非空、绝对路径、无换行/控制字符。
func ValidDir(dir string) bool {
	dir = strings.TrimSpace(dir)
	if dir == "" || !filepath.IsAbs(dir) {
		return false
	}
	return !hasCtrl(dir)
}

func hasCtrl(s string) bool {
	for _, r := range s {
		if r == '\n' || r == '\r' || r < 0x20 {
			return true
		}
	}
	return false
}

// ProjectSpec 是生成一个项目进程启动命令所需的全部字段。调用方须保证各字段已通过对应 Valid* 校验。
type ProjectSpec struct {
	Name       string
	ProjectDir string // 项目代码目录(工作目录)
	VenvDir    string // venv 根目录;其 bin/ 下有 python/gunicorn/uvicorn
	StartKind  string // gunicorn | uvicorn | script
	AppTarget  string // "module:app" 或脚本相对路径
	Port       int
	Workers    int // gunicorn/uvicorn worker 数;<1 时取 1
}

// BuildCommand 生成进程启动命令的参数数组。绝不返回 shell 字符串,供 exec.Command 直接消费。
// 各字段已校验,危险字符已被 Valid* 挡掉。
func BuildCommand(s ProjectSpec) []string {
	bin := filepath.Join(s.VenvDir, "bin")
	workers := s.Workers
	if workers < 1 {
		workers = 1
	}
	bindAddr := fmt.Sprintf("0.0.0.0:%d", s.Port)
	switch s.StartKind {
	case StartGunicorn:
		return []string{
			filepath.Join(bin, "gunicorn"),
			"--workers", fmt.Sprintf("%d", workers),
			"--bind", bindAddr,
			s.AppTarget,
		}
	case StartUvicorn:
		return []string{
			filepath.Join(bin, "uvicorn"),
			"--host", "0.0.0.0",
			"--port", fmt.Sprintf("%d", s.Port),
			"--workers", fmt.Sprintf("%d", workers),
			s.AppTarget,
		}
	default: // StartScript
		return []string{
			filepath.Join(bin, "python"),
			s.AppTarget,
		}
	}
}

// Provisioner 抽象 venv 创建与依赖安装的外部副作用,便于 mock 测 handler。
type Provisioner interface {
	// CreateVenv 用 interpreter(如 python3.11)在 venvDir 创建虚拟环境。
	CreateVenv(interpreter, venvDir string) error
	// InstallRequirements 在 venvDir 内执行 pip install -r reqPath。
	InstallRequirements(venvDir, reqPath string) error
}

// Runner 抽象进程管理(supervisor/systemd/gunicorn 任选)的外部副作用。
// 一个项目对应一个受管单元,用 name 唯一标识。
type Runner interface {
	// Apply 注册/更新项目对应的进程单元(写配置 + reload)。argv 是已构造好的启动命令。
	Apply(name, workDir string, argv []string) error
	// Remove 注销项目进程单元(不存在视为成功)。
	Remove(name string) error
	// Action 执行 start|stop|restart,返回合并输出。
	Action(verb, name string) (string, error)
	// Status 返回项目进程状态文本。
	Status(name string) (string, error)
	// Logs 返回项目日志末尾 lines 行。
	Logs(name string, lines int) (string, error)
	// Available 报告底层进程管理器是否可用(供 HealthCheck)。
	Available() error
}

// 允许的进程动词。
var allowedVerbs = map[string]bool{"start": true, "stop": true, "restart": true}

// execProvisioner 用 python -m venv 与 pip 的真实实现。
type execProvisioner struct{}

// NewProvisioner 返回基于 python -m venv / pip 的真实 Provisioner。
func NewProvisioner() Provisioner { return execProvisioner{} }

func (execProvisioner) CreateVenv(interpreter, venvDir string) error {
	if !ValidPythonVersion(interpreter) {
		return fmt.Errorf("python: invalid interpreter %q", interpreter)
	}
	bin := interpreter
	if !strings.HasPrefix(interpreter, "python") {
		bin = "python" + interpreter
	}
	out, err := exec.Command(bin, "-m", "venv", venvDir).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create venv: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execProvisioner) InstallRequirements(venvDir, reqPath string) error {
	pip := filepath.Join(venvDir, "bin", "pip")
	out, err := exec.Command(pip, "install", "-r", reqPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("pip install: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ProvisionAvailable 供 HealthCheck:python3 是否在 PATH。
func ProvisionAvailable() error {
	_, err := exec.LookPath("python3")
	return err
}

// supervisorRunner 是基于 supervisorctl 的真实 Runner:把项目渲染成 supervisor program。
type supervisorRunner struct {
	confDir string // supervisor 程序配置目录
	logDir  string // 项目日志目录
}

// NewSupervisorRunner 返回基于 supervisor 的 Runner。
func NewSupervisorRunner(confDir, logDir string) Runner {
	return &supervisorRunner{confDir: confDir, logDir: logDir}
}

func (rn *supervisorRunner) Apply(name, workDir string, argv []string) error {
	path, err := safeConfPath(rn.confDir, name)
	if err != nil {
		return err
	}
	cfg := renderSupervisorConfig(name, workDir, argv, rn.logDir)
	if err := os.WriteFile(path, []byte(cfg), 0o644); err != nil {
		return err
	}
	return reloadSupervisor()
}

func (rn *supervisorRunner) Remove(name string) error {
	path, err := safeConfPath(rn.confDir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return reloadSupervisor()
}

func (rn *supervisorRunner) Action(verb, name string) (string, error) {
	if !allowedVerbs[verb] {
		return "", fmt.Errorf("python: verb %q not allowed", verb)
	}
	if !ValidProjectName(name) {
		return "", fmt.Errorf("python: invalid project name %q", name)
	}
	out, err := exec.Command("supervisorctl", verb, name).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("supervisorctl %s %s: %w", verb, name, err)
	}
	return text, nil
}

func (rn *supervisorRunner) Status(name string) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("python: invalid project name %q", name)
	}
	// status 退出码非 0 属正常(项目停止),不当错误抛。
	out, _ := exec.Command("supervisorctl", "status", name).CombinedOutput()
	return strings.TrimSpace(string(out)), nil
}

func (rn *supervisorRunner) Logs(name string, lines int) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("python: invalid project name %q", name)
	}
	if lines <= 0 || lines > 10000 {
		lines = 200
	}
	out, err := exec.Command("supervisorctl", "tail", fmt.Sprintf("-%d", lines), name).CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("supervisorctl tail %s: %w", name, err)
	}
	return text, nil
}

func (rn *supervisorRunner) Available() error {
	_, err := exec.LookPath("supervisorctl")
	return err
}

func reloadSupervisor() error {
	if out, err := exec.Command("supervisorctl", "reread").CombinedOutput(); err != nil {
		return fmt.Errorf("supervisorctl reread: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("supervisorctl", "update").CombinedOutput(); err != nil {
		return fmt.Errorf("supervisorctl update: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// renderSupervisorConfig 用固定模板把项目渲染成 supervisor program。argv 已是参数数组,
// 各元素经 BuildCommand 构造、字段已校验,空格分隔写入 command= 行不引入注入。
func renderSupervisorConfig(name, workDir string, argv []string, logDir string) string {
	logDir = strings.TrimRight(strings.TrimSpace(logDir), "/")
	var b strings.Builder
	fmt.Fprintf(&b, "[program:%s]\n", name)
	fmt.Fprintf(&b, "command=%s\n", strings.Join(argv, " "))
	fmt.Fprintf(&b, "directory=%s\n", strings.TrimSpace(workDir))
	fmt.Fprintf(&b, "autostart=true\n")
	fmt.Fprintf(&b, "autorestart=true\n")
	fmt.Fprintf(&b, "stdout_logfile=%s/%s.out.log\n", logDir, name)
	fmt.Fprintf(&b, "stderr_logfile=%s/%s.err.log\n", logDir, name)
	return b.String()
}

// safeConfPath 把 confDir/name.conf 限定在 confDir 内。name 须先过白名单校验
// (无路径分隔符),这里再做一层词法兜底,确保不逃逸目录。
func safeConfPath(confDir, name string) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("python: invalid project name %q", name)
	}
	confDir = filepath.Clean(confDir)
	path := filepath.Join(confDir, name+".conf")
	if filepath.Dir(path) != confDir {
		return "", fmt.Errorf("python: config path %q escapes %q", path, confDir)
	}
	return path, nil
}
