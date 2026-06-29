package system

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// XPanel 在用户 crontab 里维护一段带标记的托管区,区外行原样保留。
// 标记带实例 key,使同机多个实例(同写 root crontab)各管各的块,互不覆盖;
// 重写时只替换本实例 key 的 BEGIN..END,保留其它实例的块与用户手工行。
//
// 旧版用过无 key 的固定标记(下方 legacy 常量)。sync 时顺带清掉旧块作迁移:
// 旧块无 key 无法归属,由首个 sync 的实例一次性认领(其内容本就是各实例互相
// 覆盖后的残留,清掉不引入新的数据丢失)。
const (
	cronLegacyBeginMarker = "# === XPANEL-CRON BEGIN (managed, do not edit) ==="
	cronLegacyEndMarker   = "# === XPANEL-CRON END ==="
)

// 实例 key 限定 [a-z0-9](InstanceKey 产出十六进制,天然满足),可安全嵌入注释行。
var (
	cronBeginKeyedRe = regexp.MustCompile(`^# === XPANEL-CRON BEGIN \(managed:([a-z0-9]+)\) ===$`)
	cronEndKeyedRe   = regexp.MustCompile(`^# === XPANEL-CRON END \(managed:([a-z0-9]+)\) ===$`)
)

func cronBeginMarker(key string) string { return "# === XPANEL-CRON BEGIN (managed:" + key + ") ===" }
func cronEndMarker(key string) string   { return "# === XPANEL-CRON END (managed:" + key + ") ===" }

// InstanceKey 把任意实例标识种子(如绝对 DB 路径)归一成稳定、同机唯一的安全 token。
// 取 SHA-256 前 12 个十六进制字符:产出恒为 [0-9a-f],绝不含换行/特殊字符,
// 可安全写进 crontab 注释行,任意种子(含注入字符)都不会产生畸形标记。
func InstanceKey(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return hex.EncodeToString(sum[:])[:12]
}

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

// RenderManagedBlock 生成本实例 key 的托管区文本(含首尾标记)。每条任务前加一行备注。
// key 须为 InstanceKey 产出([a-z0-9]);调用方须保证 job 的 Expr/Command 已通过校验。
func RenderManagedBlock(key string, jobs []CronJobLine) string {
	var b strings.Builder
	b.WriteString(cronBeginMarker(key))
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
	b.WriteString(cronEndMarker(key))
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

// MergeManagedBlock 把本实例 key 的 managed 区合并进已有 crontab:只替换本实例
// key 的旧块(及旧式无 key 块,作迁移),其它实例的块与用户手工行原样保留;
// 本实例无旧块时追加到末尾。managed 须由 RenderManagedBlock(key, ...) 生成。
func MergeManagedBlock(existing, managed, key string) string {
	stripped := stripManagedBlock(existing, key)
	stripped = strings.TrimRight(stripped, "\n")
	if stripped == "" {
		return managed
	}
	return stripped + "\n" + managed
}

// stripManagedBlock 去掉 existing 中归属本实例 key 的托管区(含标记)以及旧式无
// key 的托管区(迁移)。其它实例 key 的块原样保留。无可删块则原样返回。
func stripManagedBlock(existing, key string) string {
	lines := strings.Split(existing, "\n")
	out := make([]string, 0, len(lines))
	stripping := false   // 正处于待删块内部
	stripLegacy := false // 待删块是旧式无 key 块(其 END 也是旧式)
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if !stripping {
			bkey, blegacy, bok := parseCronBegin(t)
			// 仅删旧式块或本实例 key 的块;其它实例 key 的块保留(连同其 BEGIN 行)。
			if bok && (blegacy || bkey == key) {
				stripping = true
				stripLegacy = blegacy
				continue
			}
			out = append(out, ln)
			continue
		}
		ekey, elegacy, eok := parseCronEnd(t)
		if eok && ((stripLegacy && elegacy) || (!stripLegacy && !elegacy && ekey == key)) {
			stripping = false
			continue
		}
		// 块体行(及不匹配的标记)一律丢弃。
	}
	return strings.Join(out, "\n")
}

// parseCronBegin 识别 BEGIN 标记行:legacy=true 表示旧式无 key 块;否则 key 为捕获到的实例 key。
func parseCronBegin(line string) (key string, legacy, ok bool) {
	if line == cronLegacyBeginMarker {
		return "", true, true
	}
	if m := cronBeginKeyedRe.FindStringSubmatch(line); m != nil {
		return m[1], false, true
	}
	return "", false, false
}

// parseCronEnd 识别 END 标记行,语义同 parseCronBegin。
func parseCronEnd(line string) (key string, legacy, ok bool) {
	if line == cronLegacyEndMarker {
		return "", true, true
	}
	if m := cronEndKeyedRe.FindStringSubmatch(line); m != nil {
		return m[1], false, true
	}
	return "", false, false
}
