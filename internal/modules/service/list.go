package service

import (
	"os/exec"
	"sort"
	"strings"
)

// Service 是 /services 端点返回的单条系统服务视图(前端按此对接)。
type Service struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Active      string `json:"active"`  // running|exited|failed|dead 等(systemctl ACTIVE 列)
	Sub         string `json:"sub"`     // SUB 列细分状态
	Enabled     string `json:"enabled"` // enabled|disabled|static 等;无 unit-file 条目时为空
}

// commandRunner 抽象两条 systemctl 列出命令,便于测试时注入样本输出
// (测试环境 systemctl 行为不定)。
type commandRunner interface {
	listUnits() (string, error)     // list-units --type=service --all
	listUnitFiles() (string, error) // list-unit-files --type=service
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
	return mergeServices(parseListUnits(unitsOut), parseListUnitFiles(filesOut)), nil
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
