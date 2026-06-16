package php

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 仅允许编辑这批常用 php.ini 指令(对标 aaPanel PHP 设置面板)。白名单之外一律拒绝,
// 防止改写危险指令(如 disable_functions、auto_prepend_file 等)造成提权或绕过沙箱。
var editableIniKeys = map[string]bool{
	"memory_limit":               true,
	"max_execution_time":         true,
	"max_input_time":             true,
	"post_max_size":              true,
	"upload_max_filesize":        true,
	"max_file_uploads":           true,
	"default_socket_timeout":     true,
	"display_errors":             true,
	"error_reporting":            true,
	"date.timezone":              true,
	"short_open_tag":             true,
	"max_input_vars":             true,
	"realpath_cache_size":        true,
	"opcache.memory_consumption": true,
}

// IniField 描述一个可表单化编辑的 php.ini 指令(供前端渲染说明/分组)。
type IniField struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Group string `json:"group"`
	Desc  string `json:"desc"`
}

// iniSchema 是白名单指令的展示元数据,顺序即前端渲染顺序。key 集合须与 editableIniKeys 一致。
var iniSchema = []IniField{
	{"memory_limit", "内存上限", "资源限制", "单进程可用内存上限,如 128M、512M、-1(无限制)"},
	{"max_execution_time", "最大执行时间", "资源限制", "脚本最长运行秒数,0 为不限"},
	{"max_input_time", "最大输入解析时间", "资源限制", "解析请求数据的最长秒数,-1 取 max_execution_time"},
	{"post_max_size", "POST 上限", "上传", "单次 POST 数据上限,需 >= upload_max_filesize"},
	{"upload_max_filesize", "上传文件上限", "上传", "单个上传文件大小上限,如 8M"},
	{"max_file_uploads", "最大上传文件数", "上传", "单请求允许上传的文件数"},
	{"default_socket_timeout", "Socket 超时", "资源限制", "基于 socket 的流默认超时秒数"},
	{"display_errors", "显示错误", "错误", "生产环境建议 Off,避免泄露路径"},
	{"error_reporting", "错误级别", "错误", "如 E_ALL & ~E_DEPRECATED & ~E_STRICT"},
	{"date.timezone", "时区", "本地化", "默认时区,如 Asia/Shanghai、UTC"},
	{"short_open_tag", "短标签", "语法", "是否允许 <? 短开标签,On/Off"},
	{"max_input_vars", "最大输入变量数", "资源限制", "单请求接受的输入变量上限"},
	{"realpath_cache_size", "realpath 缓存", "性能", "realpath 缓存大小,如 4096k"},
	{"opcache.memory_consumption", "OPcache 内存", "性能", "OPcache 共享内存大小(MB)"},
}

// iniKeyRe 校验指令名:字母数字 . _,与白名单一道挡注入。
var iniKeyRe = regexp.MustCompile(`^[a-zA-Z0-9._]+$`)

// iniValueForbidden 是值里禁止的字符:换行/回车/NUL 会截断或注入新指令行,
// "[" 会被解析成新 section 头。纵深防御,即便值只是写回单行 key = value。
const iniValueForbidden = "\n\r\x00[]"

// ValidIniKey 报告 key 是允许编辑的 php.ini 指令名。
func ValidIniKey(key string) bool {
	return iniKeyRe.MatchString(key) && editableIniKeys[key]
}

// ValidIniValue 报告 value 可安全写入 php.ini(无截断/注入字符)。
func ValidIniValue(value string) bool {
	return !strings.ContainsAny(value, iniValueForbidden)
}

// validateIniChanges 校验一批 ini 改动:每个 key 须在白名单内,每个 value 须安全。
func validateIniChanges(changes map[string]string) error {
	for k, v := range changes {
		if !ValidIniKey(k) {
			return fmt.Errorf("php: ini key %q not editable", k)
		}
		if !ValidIniValue(v) {
			return fmt.Errorf("php: ini value for %q contains forbidden characters", k)
		}
	}
	return nil
}

// maxRawIni 是原始 php.ini 编辑的字节上限,挡掉异常大写入。
const maxRawIni = 1 << 20 // 1 MiB

// validateRawIni 校验整份 php.ini 文本可安全落盘:无 NUL(会截断 C 读取),不超限。
// 不做指令白名单——原始编辑就是要放开,但仍挡掉破坏文件的字节。
func validateRawIni(content string) error {
	if len(content) > maxRawIni {
		return fmt.Errorf("php: ini content exceeds %d bytes", maxRawIni)
	}
	if strings.ContainsRune(content, '\x00') {
		return fmt.Errorf("php: ini content contains NUL byte")
	}
	return nil
}

// dangerousFuncs 是可经 disable_functions 管理的常见危险函数白名单。
// 仅允许增删这批已知函数名,挡掉把任意字符串塞进 disable_functions(配置注入)。
var dangerousFuncs = map[string]bool{
	"exec": true, "passthru": true, "shell_exec": true, "system": true,
	"proc_open": true, "popen": true, "proc_get_status": true, "proc_close": true,
	"proc_terminate": true, "proc_nice": true, "pcntl_exec": true,
	"dl": true, "putenv": true, "symlink": true, "link": true,
	"chgrp": true, "chown": true, "chmod": true, "show_source": true,
	"highlight_file": true, "ini_alter": true, "openlog": true, "syslog": true,
}

// DangerousFuncList 返回可管理的危险函数白名单(排序,供前端展示候选)。
func DangerousFuncList() []string {
	out := make([]string, 0, len(dangerousFuncs))
	for f := range dangerousFuncs {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// parseDisableFunctions 从 php.ini 文本抽出 disable_functions 当前列表(逗号分隔,去空白)。
func parseDisableFunctions(content string) []string {
	val := iniRawValue(content, "disable_functions")
	if val == "" {
		return []string{}
	}
	var out []string
	for _, f := range strings.Split(val, ",") {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// iniRawValue 返回顶层某 key 的原始值(不经白名单),未找到返回空串。
func iniRawValue(content, key string) string {
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(line[:eq]) == key {
			return strings.TrimSpace(line[eq+1:])
		}
	}
	return ""
}

// validateDisableFunctions 校验列表里每个名字都是已知危险函数(白名单内),且去重。
func validateDisableFunctions(funcs []string) error {
	for _, f := range funcs {
		if !dangerousFuncs[f] {
			return fmt.Errorf("php: %q is not a manageable dangerous function", f)
		}
	}
	return nil
}

// applyDisableFunctions 把 disable_functions 设为给定列表(去重排序),原地替换或追加该行。
func applyDisableFunctions(content string, funcs []string) string {
	seen := make(map[string]bool, len(funcs))
	var dedup []string
	for _, f := range funcs {
		if !seen[f] {
			seen[f] = true
			dedup = append(dedup, f)
		}
	}
	sort.Strings(dedup)
	return applyIniLine(content, "disable_functions", strings.Join(dedup, ","))
}

// applyIniLine 原地替换顶层 key 的值;未找到则追加。value 须已校验无换行/NUL。
func applyIniLine(content, key, value string) string {
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(content))
	first, replaced := true, false
	for sc.Scan() {
		raw := sc.Text()
		if !first {
			b.WriteByte('\n')
		}
		first = false
		trimmed := strings.TrimSpace(raw)
		if !replaced && trimmed != "" && !strings.HasPrefix(trimmed, ";") && !strings.HasPrefix(trimmed, "[") {
			if eq := strings.IndexByte(trimmed, '='); eq >= 0 && strings.TrimSpace(trimmed[:eq]) == key {
				b.WriteString(key + " = " + value)
				replaced = true
				continue
			}
		}
		b.WriteString(raw)
	}
	if !replaced {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(key + " = " + value)
	}
	return b.String()
}

// parseIni 从 php.ini 文本里抽出白名单指令的当前值。只读视图,不保留注释/section。
// 仅扫描顶层 "key = value" 行(忽略以 ; 或 [ 开头的行)。
func parseIni(content string) map[string]string {
	out := make(map[string]string)
	sc := bufio.NewScanner(strings.NewReader(content))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "[") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !editableIniKeys[key] {
			continue
		}
		val := strings.TrimSpace(line[eq+1:])
		out[key] = val
	}
	return out
}

// applyIniChanges 把 changes 合并进 ini 文本:命中的 key 原地改值(保留行序/注释),
// 未出现的 key 追加到文末。changes 须已 validateIniChanges 通过。
func applyIniChanges(content string, changes map[string]string) string {
	if len(changes) == 0 {
		return content
	}
	pending := make(map[string]string, len(changes))
	for k, v := range changes {
		pending[k] = v
	}
	var b strings.Builder
	sc := bufio.NewScanner(strings.NewReader(content))
	first := true
	for sc.Scan() {
		raw := sc.Text()
		if !first {
			b.WriteByte('\n')
		}
		first = false
		trimmed := strings.TrimSpace(raw)
		replaced := false
		if trimmed != "" && !strings.HasPrefix(trimmed, ";") && !strings.HasPrefix(trimmed, "[") {
			if eq := strings.IndexByte(trimmed, '='); eq >= 0 {
				key := strings.TrimSpace(trimmed[:eq])
				if v, ok := pending[key]; ok {
					b.WriteString(key + " = " + v)
					delete(pending, key)
					replaced = true
				}
			}
		}
		if !replaced {
			b.WriteString(raw)
		}
	}
	// 剩余未命中的 key 追加到末尾。
	for k, v := range pending {
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(k + " = " + v)
	}
	return b.String()
}
