package php

import (
	"bufio"
	"fmt"
	"regexp"
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
