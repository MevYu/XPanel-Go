package service

import (
	"context"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Service 是 /services 端点返回的单条系统服务视图(前端按此对接)。
type Service struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      string `json:"active"`  // running|exited|failed|dead 等(systemctl ACTIVE 列)
	Sub         string `json:"sub"`     // SUB 列细分状态
	Enabled     string `json:"enabled"` // enabled|disabled|static 等;无 unit-file 条目时为空
	Version     string `json:"version"` // 尽力探测的版本号;未知/失败为空
}

// commandRunner 抽象 systemctl 列出命令与版本探测,便于测试时注入样本输出
// (测试环境 systemctl 与各服务二进制行为不定)。
type commandRunner interface {
	listUnits() (string, error)        // list-units --type=service --all
	listUnitFiles() (string, error)    // list-unit-files --type=service
	serviceVersion(name string) string // 尽力探测版本,失败返回空
}

// systemctlRunner 是 commandRunner 的真实实现,参数数组执行,绝不拼 shell。
type systemctlRunner struct{}

func (systemctlRunner) listUnits() (string, error) {
	out, err := exec.Command("systemctl", "list-units",
		"--type=service", "--all", "--no-pager", "--plain").Output()
	return string(out), err
}

func (systemctlRunner) listUnitFiles() (string, error) {
	out, err := exec.Command("systemctl", "list-unit-files",
		"--type=service", "--no-pager", "--plain").Output()
	return string(out), err
}

// versionProbe 描述某服务的版本探测命令与输出解析正则(子组 1 为版本)。
type versionProbe struct {
	cmd []string // 参数数组:bin + args
	re  *regexp.Regexp
}

// 版本号通配:形如 1.2.3、5.7、7.0.11 等。
var verToken = regexp.MustCompile(`(\d+(?:\.\d+)+)`)

// versionProbes 按服务基名(去 .service)映射探测命令。键为已知服务的常见别名。
var versionProbes = map[string]versionProbe{
	"nginx":        {cmd: []string{"nginx", "-v"}, re: verToken}, // 版本走 STDERR
	"php":          {cmd: []string{"php", "-v"}, re: verToken},
	"php-fpm":      {cmd: []string{"php", "-v"}, re: verToken},
	"mysql":        {cmd: []string{"mysqld", "--version"}, re: verToken},
	"mysqld":       {cmd: []string{"mysqld", "--version"}, re: verToken},
	"mariadb":      {cmd: []string{"mysqld", "--version"}, re: verToken},
	"redis":        {cmd: []string{"redis-server", "--version"}, re: verToken},
	"redis-server": {cmd: []string{"redis-server", "--version"}, re: verToken},
}

// serviceVersion 对已知服务尽力探测版本,任何错误一律返回空,绝不影响列表。
func (systemctlRunner) serviceVersion(name string) string {
	base := strings.TrimSuffix(name, ".service")
	p, ok := versionProbes[base]
	if !ok {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// 部分工具版本写 STDERR(如 nginx -v),用 CombinedOutput 合并。
	out, _ := exec.CommandContext(ctx, p.cmd[0], p.cmd[1:]...).CombinedOutput()
	m := p.re.FindSubmatch(out)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// listServices 取两条命令输出并合并成排序后的服务列表。
func listServices(r commandRunner) ([]Service, error) {
	unitsOut, err := r.listUnits()
	if err != nil {
		return nil, err
	}
	filesOut, err := r.listUnitFiles()
	if err != nil {
		return nil, err
	}
	services := mergeServices(parseListUnits(unitsOut), parseListUnitFiles(filesOut))
	for i := range services {
		services[i].Version = r.serviceVersion(services[i].Name)
	}
	return services, nil
}

// parseListUnits 解析 `list-units --plain` 输出。
// 列:UNIT LOAD ACTIVE SUB DESCRIPTION。遇空行即止(后接图例/计数行)。
func parseListUnits(out string) map[string]Service {
	res := map[string]Service{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			break // 空行后是图例,停止解析
		}
		// 5 段:前 4 段单字段,DESCRIPTION 保留其内部空格。
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		name := f[0]
		desc := ""
		if len(f) > 4 {
			desc = strings.Join(f[4:], " ")
		}
		res[name] = Service{Name: name, Active: f[2], Sub: f[3], Description: desc}
	}
	return res
}

// parseListUnitFiles 解析 `list-unit-files --plain` 输出,映射 unit -> STATE。
// 列:UNIT FILE STATE [VENDOR PRESET]。遇空行即止。
func parseListUnitFiles(out string) map[string]string {
	res := map[string]string{}
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) == "" {
			break
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		res[f[0]] = f[1]
	}
	return res
}

// mergeServices 把 enabled 状态贴到各 unit,并按 name 排序稳定输出。
func mergeServices(units map[string]Service, files map[string]string) []Service {
	out := make([]Service, 0, len(units))
	for name, s := range units {
		s.Enabled = files[name] // 缺失为空字符串
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
