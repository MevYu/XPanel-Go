package cron

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/MevYu/XPanel-Go/internal/system"
)

func itoaInt(n int) string { return strconv.Itoa(n) }

// 任务类型,对照 aaPanel 计划任务。每种类型决定如何构造真正执行的命令。
const (
	taskCommand    = "command"     // 裸命令(经 sh -c)
	taskShell      = "shell"       // Shell 脚本内容,写入脚本文件后 sh 执行
	taskReleaseMem = "release_mem" // 释放内存(drop_caches)
	taskLogCut     = "log_cut"     // 日志切割:清空指定文件
	taskURL        = "url"         // 访问指定 URL(curl)
	taskBackupSite = "backup_site" // 预留:网站备份(与 sites 模块联动)
	taskBackupDB   = "backup_db"   // 预留:数据库备份(与 database 模块联动)
)

// payload 持有各类型任务的参数,按类型取用。整体 JSON 落库到 cron_jobs.payload。
type payload struct {
	Command string `json:"command,omitempty"` // command 类型的命令行
	Script  string `json:"script,omitempty"`  // shell 类型的脚本内容
	URL     string `json:"url,omitempty"`     // url 类型目标
	Path    string `json:"path,omitempty"`    // log_cut 的日志文件路径(相对 root)
	Target  string `json:"target,omitempty"`  // backup_* 的目标名(站点名/库名)
	Timeout int    `json:"timeout,omitempty"` // url 请求超时秒,默认 30
}

// validTaskType 报告 t 是否受支持的任务类型。
func validTaskType(t string) bool {
	switch t {
	case taskCommand, taskShell, taskReleaseMem, taskLogCut, taskURL, taskBackupSite, taskBackupDB:
		return true
	}
	return false
}

// validatePayload 按类型校验参数,防注入。root 为 log_cut 路径的限定根。
// 返回校验过的 payload 副本(清理后的字段)。
func validatePayload(typ string, p payload, root string) (payload, error) {
	switch typ {
	case taskCommand:
		cmd := strings.TrimSpace(p.Command)
		if !system.ValidCronCommand(cmd) {
			return payload{}, fmt.Errorf("command: empty or contains forbidden chars (newline/%%/control)")
		}
		return payload{Command: cmd}, nil

	case taskShell:
		if strings.TrimSpace(p.Script) == "" {
			return payload{}, fmt.Errorf("shell: script is empty")
		}
		if strings.ContainsRune(p.Script, 0) {
			return payload{}, fmt.Errorf("shell: script contains NUL")
		}
		return payload{Script: p.Script}, nil

	case taskReleaseMem:
		return payload{}, nil // 无参数

	case taskLogCut:
		rel := strings.TrimSpace(p.Path)
		if rel == "" {
			return payload{}, fmt.Errorf("log_cut: path is empty")
		}
		if _, err := system.SafeJoin(root, rel); err != nil {
			return payload{}, fmt.Errorf("log_cut: invalid path: %w", err)
		}
		return payload{Path: rel}, nil

	case taskURL:
		u := strings.TrimSpace(p.URL)
		if err := validateHTTPURL(u); err != nil {
			return payload{}, fmt.Errorf("url: %w", err)
		}
		to := p.Timeout
		if to <= 0 {
			to = 30
		}
		if to > 3600 {
			return payload{}, fmt.Errorf("url: timeout too large")
		}
		return payload{URL: u, Timeout: to}, nil

	case taskBackupSite, taskBackupDB:
		tgt := strings.TrimSpace(p.Target)
		if !validBackupTarget(tgt) {
			return payload{}, fmt.Errorf("backup: target name empty or has unsafe chars")
		}
		return payload{Target: tgt}, nil
	}
	return payload{}, fmt.Errorf("unknown task type %q", typ)
}

// derivedCommand 返回任务在 crontab 托管区里展示的等价命令(仅供展示/兼容)。
// 真正执行由模块内调度器经 runner 完成,不依赖此串。
func derivedCommand(typ string, p payload) string {
	switch typ {
	case taskCommand:
		return p.Command
	case taskShell:
		return "# xpanel shell script (managed in-process)"
	case taskReleaseMem:
		return "sync && echo 3 > /proc/sys/vm/drop_caches"
	case taskLogCut:
		return "truncate -s 0 " + p.Path
	case taskURL:
		return "curl -fsS --max-time " + strconv.Itoa(p.Timeout) + " " + p.URL
	case taskBackupSite:
		return "# xpanel backup site: " + p.Target
	case taskBackupDB:
		return "# xpanel backup db: " + p.Target
	}
	return ""
}

// validateHTTPURL 仅允许 http/https 绝对 URL,带 host。
func validateHTTPURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("malformed: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if u.Host == "" {
		return fmt.Errorf("missing host")
	}
	return nil
}

// validBackupTarget 仅允许字母数字、点、下划线、连字符(站点/库名)。
func validBackupTarget(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		ok := r == '.' || r == '_' || r == '-' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return false
		}
	}
	return true
}
