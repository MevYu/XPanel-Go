package system

import (
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// XPanel 在用户 crontab 里维护一段带标记的托管区,区外行原样保留。
// 重写时只替换 BEGIN..END 之间的内容,避免误删用户手工添加的任务。
const (
	cronBeginMarker = "# === XPANEL-CRON BEGIN (managed, do not edit) ==="
	cronEndMarker   = "# === XPANEL-CRON END ==="
)

// cron 字段:5 段标准字段。每段允许数字、* , - / 以及月/周名缩写字母。
// 仅做注入防护与基本结构校验,不做语义范围校验(交给 crontab 自身)。
var cronFieldRe = regexp.MustCompile(`^[0-9*,/A-Za-z-]{1,64}$`)

// ValidCronExpr 校验 5 段 cron 表达式。拒绝换行/控制字符与字段外的危险字符。
func ValidCronExpr(expr string) bool {
	fields := strings.Fields(strings.TrimSpace(expr))
	if len(fields) != 5 {
		return false
	}
	for _, f := range fields {
		if !cronFieldRe.MatchString(f) {
			return false
		}
	}
	return true
}

// ValidCronCommand 校验要写入 crontab 的命令:非空,且不含会破坏 crontab 行结构
// 的换行/回车/其它控制字符(% 在 crontab 里是 stdin 分隔符,也禁止)。
func ValidCronCommand(cmd string) bool {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return false
	}
	for _, r := range cmd {
		if r == '\n' || r == '\r' || r == '%' || r < 0x20 {
			return false
		}
	}
	return true
}

// CronJobLine 是要写进 crontab 托管区的一条任务。
type CronJobLine struct {
	ID      int64
	Expr    string
	Command string
	Comment string
}

// CrontabAvailable 供 HealthCheck:crontab 命令是否在 PATH。
func CrontabAvailable() error {
	_, err := exec.LookPath("crontab")
	return err
}

// ReadCrontab 读当前用户 crontab。无 crontab(crontab -l 退出码 1)视为空,不报错。
func ReadCrontab() (string, error) {
	out, err := exec.Command("crontab", "-l").CombinedOutput()
	if err != nil {
		// "no crontab for <user>" 时 crontab -l 退出码非 0,这不是错误。
		text := string(out)
		if strings.Contains(text, "no crontab") {
			return "", nil
		}
		return "", fmt.Errorf("crontab -l: %w: %s", err, strings.TrimSpace(text))
	}
	return string(out), nil
}

// WriteCrontab 用 crontab - 从 stdin 整体替换当前用户 crontab。
func WriteCrontab(content string) error {
	cmd := exec.Command("crontab", "-")
	cmd.Stdin = strings.NewReader(content)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("crontab -: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

// RenderManagedBlock 生成托管区文本(含首尾标记)。每条任务前加一行备注。
// 调用方须保证 job 的 Expr/Command 已通过校验。
func RenderManagedBlock(jobs []CronJobLine) string {
	var b strings.Builder
	b.WriteString(cronBeginMarker)
	b.WriteByte('\n')
	for _, j := range jobs {
		if j.Comment != "" {
			// 备注同样过滤换行,防止越出注释行。
			b.WriteString("# ")
			b.WriteString(sanitizeComment(j.Comment))
			b.WriteByte('\n')
		}
		fmt.Fprintf(&b, "%s %s\n", strings.TrimSpace(j.Expr), strings.TrimSpace(j.Command))
	}
	b.WriteString(cronEndMarker)
	b.WriteByte('\n')
	return b.String()
}

func sanitizeComment(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r < 0x20 {
			return ' '
		}
		return r
	}, s)
}

// MergeManagedBlock 把 managed 区合并进已有 crontab:替换旧托管区,
// 保留区外用户行;若无旧托管区则追加到末尾。
func MergeManagedBlock(existing, managed string) string {
	stripped := stripManagedBlock(existing)
	stripped = strings.TrimRight(stripped, "\n")
	if stripped == "" {
		return managed
	}
	return stripped + "\n" + managed
}

// stripManagedBlock 去掉 existing 中的托管区(含标记)。无标记则原样返回。
func stripManagedBlock(existing string) string {
	lines := strings.Split(existing, "\n")
	var out []string
	inBlock := false
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if t == cronBeginMarker {
			inBlock = true
			continue
		}
		if t == cronEndMarker {
			inBlock = false
			continue
		}
		if inBlock {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}
