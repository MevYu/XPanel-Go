package php

import (
	"os"
	"sort"
	"strings"
)

// detectVersions 扫描安装基目录,返回每个子目录名为合法版本号且含 bin/php 的版本列表。
// 目录不存在 / 不可读时返回空列表(环境无 PHP 视为正常)。
func detectVersions(base string) []string {
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if !ValidVersion(name) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// parseModules 把 php -m 输出解析成扩展名列表。忽略 "[...]" 分节头与空行,
// 只保留通过扩展名白名单的行(防把异常输出当扩展)。
func parseModules(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		name := strings.TrimSpace(line)
		if name == "" || strings.HasPrefix(name, "[") {
			continue
		}
		if !ValidExtName(name) {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
