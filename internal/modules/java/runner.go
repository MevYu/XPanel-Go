package java

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ProcessManager 抽象 Java 项目的全部进程副作用:写/删配置、reload、启停查、读日志、
// 部署/下线 Tomcat war、检测已装 JDK 版本。便于用 mock 测 handler 与渲染逻辑,
// 也便于切换 supervisor/systemd 后端。
//
// 默认实现 supervisorManager 走 supervisor(conf.d 配置 + supervisorctl),与本项目进程守护一致。
// jar/war 项目用 java -jar 起独立进程;tomcat 项目把 war 部署进 Tomcat webapps 目录。
type ProcessManager interface {
	// Apply 把 spec 渲染成进程配置写入 confDir/<name>.conf,并 reload 使其生效(jar/war)。
	Apply(confDir string, spec ProcessSpec) error
	// Remove 删除 confDir/<name>.conf 并 reload(不存在视为成功)。
	Remove(confDir, name string) error
	// Deploy 把 war 部署进 Tomcat webapps(以 name 作 context)。
	Deploy(tomcatDir, name, warPath string) error
	// Undeploy 从 Tomcat webapps 下线 name 对应的 war 与解包目录。
	Undeploy(tomcatDir, name string) error
	// Action 执行 start|stop|restart,返回合并输出(jar/war 走 supervisorctl)。
	Action(verb, name string) (string, error)
	// Status 返回进程状态文本。
	Status(name string) (string, error)
	// TailLog 返回最近 lines 行日志;stderr 为 true 取错误流。
	TailLog(name string, lines int, stderr bool) (string, error)
	// JavaVersions 返回检测到的已装 JDK 版本(尽力而为,失败返回空)。
	JavaVersions() []string
	// Available 报告后端是否可用(供 HealthCheck):java 与进程管理器均在 PATH。
	Available() error
}

// ProcessSpec 是渲染一个 jar/war Java 项目进程配置所需的全部字段。
// 调用方须保证各字段已通过对应 Valid* 校验。
type ProcessSpec struct {
	Name         string
	ArtifactPath string // jar/war 绝对路径(已校验在基目录内)
	JVMArgs      string // JVM 参数行(已校验,渲染时拆数组)
	Port         int    // 注入 SERVER_PORT 环境变量
	JavaPath     string // java 可执行文件所在目录;非空时前置到 PATH
	LogDir       string
}

// 允许的状态变更动词。
var allowedVerbs = map[string]bool{"start": true, "stop": true, "restart": true}

// renderConfig 用固定模板生成 supervisor [program:x] 配置(jar/war 项目)。
// 字段已校验,JVM 参数拆成独立词后用空格拼回 command 行(每个词无 shell 元字符),
// 危险字符已被 Valid* 挡掉,非拼接式注入。
func renderConfig(s ProcessSpec) string {
	logDir := strings.TrimRight(strings.TrimSpace(s.LogDir), "/")
	pathEnv := "%(ENV_PATH)s"
	javaBin := "java"
	if dir := strings.TrimSpace(s.JavaPath); dir != "" {
		pathEnv = dir + ":%(ENV_PATH)s"
		javaBin = filepath.Join(dir, "java")
	}
	cmd := javaBin
	if args := strings.Join(splitArgs(s.JVMArgs), " "); args != "" {
		cmd += " " + args
	}
	cmd += " -jar " + strings.TrimSpace(s.ArtifactPath)

	var b strings.Builder
	fmt.Fprintf(&b, "[program:%s]\n", s.Name)
	fmt.Fprintf(&b, "command=%s\n", cmd)
	fmt.Fprintf(&b, "directory=%s\n", filepath.Dir(strings.TrimSpace(s.ArtifactPath)))
	fmt.Fprintf(&b, "autostart=true\n")
	fmt.Fprintf(&b, "autorestart=true\n")
	fmt.Fprintf(&b, "environment=SERVER_PORT=\"%d\",PATH=\"%s\"\n", s.Port, pathEnv)
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

func (supervisorManager) Deploy(tomcatDir, name, warPath string) error {
	dst, err := safeWebappPath(tomcatDir, name)
	if err != nil {
		return err
	}
	if !ValidProjectName(name) {
		return fmt.Errorf("java: invalid project name %q", name)
	}
	data, err := os.ReadFile(warPath)
	if err != nil {
		return fmt.Errorf("java: read war %q: %w", warPath, err)
	}
	return os.WriteFile(dst, data, 0o644)
}

func (supervisorManager) Undeploy(tomcatDir, name string) error {
	dst, err := safeWebappPath(tomcatDir, name)
	if err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Tomcat 解包目录与 war 同名(去掉 .war 后缀)。
	exploded := strings.TrimSuffix(dst, ".war")
	if err := os.RemoveAll(exploded); err != nil {
		return err
	}
	return nil
}

func (supervisorManager) Action(verb, name string) (string, error) {
	if !allowedVerbs[verb] {
		return "", fmt.Errorf("java: verb %q not allowed", verb)
	}
	if !ValidProjectName(name) {
		return "", fmt.Errorf("java: invalid project name %q", name)
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
		return "", fmt.Errorf("java: invalid project name %q", name)
	}
	// status 退出码非 0 属正常(进程停止),不当错误抛。
	out, _ := exec.Command("supervisorctl", "status", name).CombinedOutput()
	return strings.TrimSpace(string(out)), nil
}

func (supervisorManager) TailLog(name string, lines int, stderr bool) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("java: invalid project name %q", name)
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

func (supervisorManager) JavaVersions() []string { return detectJavaVersions() }

func (supervisorManager) Available() error {
	if _, err := exec.LookPath("java"); err != nil {
		return fmt.Errorf("java not in PATH: %w", err)
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

// detectJavaVersions 尽力检测已装 JDK 版本:取 PATH 中 java -version,再扫常见多版本目录。
func detectJavaVersions() []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	// java -version 写到 stderr,首行形如 openjdk version "17.0.9"。
	if b, err := exec.Command("java", "-version").CombinedOutput(); err == nil {
		add(parseJavaVersion(string(b)))
	}
	// 发行版常把多 JDK 装在版本目录下,目录名即版本(java-17-openjdk 等)。
	for _, base := range []string{"/usr/lib/jvm", "/opt/jdk", "/usr/java"} {
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

// parseJavaVersion 从 java -version 输出首行取引号内版本号,如 17.0.9。
func parseJavaVersion(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if i := strings.Index(line, "\""); i >= 0 {
			if j := strings.Index(line[i+1:], "\""); j >= 0 {
				return line[i+1 : i+1+j]
			}
		}
	}
	return ""
}

// safeConfPath 把 confDir/name.conf 限定在 confDir 内。name 须先过白名单校验
// (无路径分隔符),这里再做一层词法兜底,确保不逃逸目录。
func safeConfPath(confDir, name string) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("java: invalid project name %q", name)
	}
	confDir = filepath.Clean(confDir)
	path := filepath.Join(confDir, name+".conf")
	if filepath.Dir(path) != confDir {
		return "", fmt.Errorf("java: config path %q escapes %q", path, confDir)
	}
	return path, nil
}

// safeWebappPath 把 tomcatDir/webapps/name.war 限定在 webapps 内。name 须先过白名单校验。
func safeWebappPath(tomcatDir, name string) (string, error) {
	if !ValidProjectName(name) {
		return "", fmt.Errorf("java: invalid project name %q", name)
	}
	webapps := filepath.Join(filepath.Clean(tomcatDir), "webapps")
	path := filepath.Join(webapps, name+".war")
	if filepath.Dir(path) != webapps {
		return "", fmt.Errorf("java: webapp path %q escapes %q", path, webapps)
	}
	return path, nil
}
