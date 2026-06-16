package php

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// FpmField 描述一个可表单化编辑的 php-fpm pool 指令。
type FpmField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Desc  string `json:"desc"`
}

// fpmSchema 是 fpm pool 白名单指令的展示元数据,顺序即渲染顺序。
var fpmSchema = []FpmField{
	{"pm", "进程管理模式", "static / dynamic / ondemand"},
	{"pm.max_children", "最大子进程数", "可同时处理请求的子进程上限"},
	{"pm.start_servers", "启动进程数", "dynamic 模式启动时创建的子进程数"},
	{"pm.min_spare_servers", "最小空闲进程", "dynamic 模式空闲进程下限"},
	{"pm.max_spare_servers", "最大空闲进程", "dynamic 模式空闲进程上限"},
	{"pm.max_requests", "进程最大请求数", "子进程处理多少请求后重启,0 不限"},
	{"request_terminate_timeout", "请求超时", "单请求最长处理时间,如 100s、0 不限"},
	{"request_slowlog_timeout", "慢日志阈值", "超过此时间记入慢日志,如 5s、0 关闭"},
}

// editableFpmKeys 是 fpm pool 可编辑指令白名单(与 fpmSchema 一致)。
var editableFpmKeys = map[string]bool{
	"pm": true, "pm.max_children": true, "pm.start_servers": true,
	"pm.min_spare_servers": true, "pm.max_spare_servers": true,
	"pm.max_requests": true, "request_terminate_timeout": true,
	"request_slowlog_timeout": true,
}

// fpmPmModes 是 pm 指令允许的取值。
var fpmPmModes = map[string]bool{"static": true, "dynamic": true, "ondemand": true}

// fpmIntKeys 是取值必须为非负整数的指令。
var fpmIntKeys = map[string]bool{
	"pm.max_children": true, "pm.start_servers": true,
	"pm.min_spare_servers": true, "pm.max_spare_servers": true,
	"pm.max_requests": true,
}

// fpmDurationRe 校验时长值:非负整数 + 可选单位(s/m/h/d),如 "100s"、"0"。
var fpmDurationRe = regexp.MustCompile(`^[0-9]+[smhd]?$`)

// validateFpmChanges 校验一批 fpm pool 改动:key 在白名单内,value 按指令语义校验。
func validateFpmChanges(changes map[string]string) error {
	for k, v := range changes {
		if !editableFpmKeys[k] {
			return fmt.Errorf("php: fpm key %q not editable", k)
		}
		if !ValidIniValue(v) {
			return fmt.Errorf("php: fpm value for %q contains forbidden characters", k)
		}
		switch {
		case k == "pm":
			if !fpmPmModes[v] {
				return fmt.Errorf("php: pm must be static/dynamic/ondemand, got %q", v)
			}
		case fpmIntKeys[k]:
			if !isNonNegInt(v) {
				return fmt.Errorf("php: fpm %q must be a non-negative integer, got %q", k, v)
			}
		case k == "request_terminate_timeout" || k == "request_slowlog_timeout":
			if !fpmDurationRe.MatchString(v) {
				return fmt.Errorf("php: fpm %q must be a duration like 100s, got %q", k, v)
			}
		}
	}
	return nil
}

// isNonNegInt 报告 s 是非负十进制整数。
func isNonNegInt(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseFpmConfig 从 pool 配置文本抽出白名单指令的当前值。
func parseFpmConfig(content string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if editableFpmKeys[key] {
			out[key] = strings.TrimSpace(line[eq+1:])
		}
	}
	return out
}

// applyFpmChanges 把 changes 合并进 pool 配置:命中原地改值(保留行序/注释),未命中追加。
// changes 须已 validateFpmChanges 通过。
func applyFpmChanges(content string, changes map[string]string) string {
	result := content
	for _, k := range sortedKeys(changes) {
		result = applyIniLine(result, k, changes[k])
	}
	return result
}

// sortedKeys 返回 map 的有序键,保证多次写入顺序确定(测试可复现)。
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
