// Package security 实现安全加固模块:SSH 加固(白名单键改写 sshd_config)、
// SSH 公钥管理、fail2ban 封禁管理、登录日志审阅。所有写操作仅 admin,
// 危险操作(改端口/禁用密码登录/解封)需 X-Confirm-Danger + 审计。
package security

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// 可改写的 sshd_config 指令白名单。任何不在此表的键一律拒绝,绝不落盘。
// value -> 该指令的取值校验函数;校验通过才允许写入。
var sshdAllowedKeys = map[string]func(string) bool{
	"Port":                   validSSHPort,
	"PermitRootLogin":        validRootLogin,
	"PasswordAuthentication": validYesNo,
	"PubkeyAuthentication":   validYesNo,
	"PermitEmptyPasswords":   validYesNo,
	"X11Forwarding":          validYesNo,
	"MaxAuthTries":           validPositiveInt,
	"ClientAliveInterval":    validNonNegInt,
	"LoginGraceTime":         validNonNegInt,
}

// 改这些键属危险操作:可能把管理员锁在门外,须二次确认。
var sshdDangerKeys = map[string]bool{
	"Port":                   true,
	"PasswordAuthentication": true,
	"PermitRootLogin":        true,
	"PubkeyAuthentication":   true,
}

// SSHKeyAllowed 报告 key 是否在 sshd_config 白名单内。
func SSHKeyAllowed(key string) bool { _, ok := sshdAllowedKeys[key]; return ok }

// SSHKeyDangerous 报告改写 key 是否属危险操作(需二次确认)。
func SSHKeyDangerous(key string) bool { return sshdDangerKeys[key] }

// ValidateSSHDirective 校验单条指令:键须在白名单,值须过该键的取值校验。
func ValidateSSHDirective(key, value string) error {
	check, ok := sshdAllowedKeys[key]
	if !ok {
		return fmt.Errorf("sshd directive %q not in whitelist", key)
	}
	if !check(value) {
		return fmt.Errorf("invalid value %q for directive %q", value, key)
	}
	return nil
}

func validYesNo(v string) bool { return v == "yes" || v == "no" }

func validRootLogin(v string) bool {
	switch v {
	case "yes", "no", "prohibit-password", "forced-commands-only":
		return true
	}
	return false
}

func validSSHPort(v string) bool {
	n, err := strconv.Atoi(v)
	return err == nil && n >= 1 && n <= 65535
}

func validPositiveInt(v string) bool {
	n, err := strconv.Atoi(v)
	return err == nil && n > 0
}

func validNonNegInt(v string) bool {
	n, err := strconv.Atoi(v)
	return err == nil && n >= 0
}

// sshKeyTypes 是 authorized_keys 允许的密钥类型前缀。
var sshKeyTypes = map[string]bool{
	"ssh-rsa":                            true,
	"ssh-ed25519":                        true,
	"ssh-dss":                            true,
	"ecdsa-sha2-nistp256":                true,
	"ecdsa-sha2-nistp384":                true,
	"ecdsa-sha2-nistp521":                true,
	"sk-ssh-ed25519@openssh.com":         true,
	"sk-ecdsa-sha2-nistp256@openssh.com": true,
}

// commentSafe 限制公钥注释字符,避免注入换行破坏 authorized_keys 行结构。
var commentSafe = regexp.MustCompile(`^[\w@.\-+ ]*$`)

// ValidatePublicKey 校验一行 OpenSSH 公钥:类型在白名单、base64 主体可解、
// 注释(可选)字符安全。返回规范化后的单行公钥(去首尾空白)。
func ValidatePublicKey(line string) (string, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("empty public key")
	}
	if strings.ContainsAny(line, "\n\r") {
		return "", fmt.Errorf("public key must be a single line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", fmt.Errorf("public key must have type and body")
	}
	if !sshKeyTypes[fields[0]] {
		return "", fmt.Errorf("unsupported key type %q", fields[0])
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", fmt.Errorf("key body is not valid base64")
	}
	if len(fields) > 2 {
		comment := strings.Join(fields[2:], " ")
		if !commentSafe.MatchString(comment) {
			return "", fmt.Errorf("key comment contains unsafe characters")
		}
	}
	return line, nil
}

// SSHControl 抽象对 sshd 的外部副作用:读改 sshd_config、备份、校验、reload。
// 便于 mock 测 handler 与白名单逻辑。
type SSHControl interface {
	// ReadDirectives 解析 sshd_config,返回白名单键的当前生效值(未设置则缺省)。
	ReadDirectives(configPath string) (map[string]string, error)
	// SetDirective 改写一条指令:改前备份原文件,改后须 Validate 通过才生效,
	// 否则回滚到备份。返回备份路径。
	SetDirective(configPath, key, value string) (backupPath string, err error)
	// Validate 执行 sshd -t -f <configPath>,校验配置语法。
	Validate(configPath string) error
	// Reload 重载 sshd 使配置生效(sshd -t 通过后调用)。
	Reload() error
	// Available 报告 sshd 是否可用(供 HealthCheck)。
	Available() error
}

// Fail2ban 抽象对 fail2ban 的外部副作用。
type Fail2ban interface {
	// Status 返回 fail2ban-client status(总览或指定 jail)。
	Status(jail string) (string, error)
	// Banned 返回指定 jail 当前被封 IP 列表。
	Banned(jail string) ([]string, error)
	// Unban 解封 jail 中的 ip。
	Unban(jail, ip string) error
	// SetJail 启停 jail。
	SetJail(jail string, enable bool) error
	// Available 报告 fail2ban-client 是否可用。
	Available() error
}

// LoginLog 抽象登录日志读取。
type LoginLog interface {
	// Recent 返回最近的登录记录(failed=true 取失败登录,否则成功)。
	Recent(failed bool, limit int) ([]LoginEntry, error)
}

// LoginEntry 是一条登录记录。
type LoginEntry struct {
	User   string `json:"user"`
	IP     string `json:"ip"`
	When   string `json:"when"`
	Failed bool   `json:"failed"`
}

// ---- exec 实现 ----

type execSSH struct{}

// NewSSHControl 返回基于 sshd 二进制的真实实现。
func NewSSHControl() SSHControl { return execSSH{} }

func (execSSH) Available() error {
	if _, err := exec.LookPath("sshd"); err != nil {
		return fmt.Errorf("security: sshd binary not found")
	}
	return nil
}

// ReadDirectives 取每个白名单键最后一次非注释赋值。
func (execSSH) ReadDirectives(configPath string) (map[string]string, error) {
	f, err := os.Open(configPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := parseDirective(sc.Text())
		if !ok || !SSHKeyAllowed(k) {
			continue
		}
		out[k] = v
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (e execSSH) SetDirective(configPath, key, value string) (string, error) {
	if err := ValidateSSHDirective(key, value); err != nil {
		return "", err
	}
	orig, err := os.ReadFile(configPath)
	if err != nil {
		return "", err
	}
	backup := configPath + ".xpanel.bak"
	if err := os.WriteFile(backup, orig, 0o600); err != nil {
		return "", fmt.Errorf("backup failed: %w", err)
	}
	updated := rewriteDirective(string(orig), key, value)
	if err := os.WriteFile(configPath, []byte(updated), 0o644); err != nil {
		return backup, fmt.Errorf("write config failed: %w", err)
	}
	if err := e.Validate(configPath); err != nil {
		// 回滚:校验失败绝不留下坏配置。
		_ = os.WriteFile(configPath, orig, 0o644)
		return backup, fmt.Errorf("sshd -t rejected new config, rolled back: %w", err)
	}
	return backup, nil
}

func (execSSH) Validate(configPath string) error {
	out, err := exec.Command("sshd", "-t", "-f", configPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sshd -t: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execSSH) Reload() error {
	out, err := exec.Command("systemctl", "reload", "sshd").CombinedOutput()
	if err != nil {
		return fmt.Errorf("reload sshd: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseDirective 解析一行 sshd_config,返回键值(忽略注释/空行)。
func parseDirective(line string) (key, value string, ok bool) {
	s := strings.TrimSpace(line)
	if s == "" || strings.HasPrefix(s, "#") {
		return "", "", false
	}
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return "", "", false
	}
	return fields[0], fields[1], true
}

// rewriteDirective 把 key 改成 value:替换首个非注释的该键行,若不存在则追加;
// 同名后续行被注释掉以确保 value 生效(sshd 以首个非注释行为准)。
func rewriteDirective(content, key, value string) string {
	lines := strings.Split(content, "\n")
	replaced := false
	for i, line := range lines {
		k, _, ok := parseDirective(line)
		if !ok || !strings.EqualFold(k, key) {
			continue
		}
		if !replaced {
			lines[i] = key + " " + value
			replaced = true
		} else {
			lines[i] = "#" + line
		}
	}
	if !replaced {
		if content != "" && !strings.HasSuffix(content, "\n") {
			lines = append(lines, "")
		}
		lines = append(lines, key+" "+value)
	}
	return strings.Join(lines, "\n")
}

// ---- authorized_keys 文件操作(非接口,纯文件,直接可测) ----

// ReadAuthorizedKeys 读取 authorized_keys,返回逐行公钥(忽略空行/注释行)。
// 文件不存在视为空列表(尚未配置任何密钥)。
func ReadAuthorizedKeys(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var keys []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keys = append(keys, line)
	}
	return keys, sc.Err()
}

// AddAuthorizedKey 把校验通过的公钥追加进 authorized_keys(幂等:已存在则不重复)。
// 目录不存在则按 0700 创建,文件按 0600 写。
func AddAuthorizedKey(path, key string) error {
	norm, err := ValidatePublicKey(key)
	if err != nil {
		return err
	}
	existing, err := ReadAuthorizedKeys(path)
	if err != nil {
		return err
	}
	for _, k := range existing {
		if k == norm {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	existing = append(existing, norm)
	return writeAuthorizedKeys(path, existing)
}

// RemoveAuthorizedKey 删除与 key 完全匹配的公钥行;不存在视为成功。
func RemoveAuthorizedKey(path, key string) error {
	target := strings.TrimSpace(key)
	existing, err := ReadAuthorizedKeys(path)
	if err != nil {
		return err
	}
	kept := make([]string, 0, len(existing))
	for _, k := range existing {
		if k != target {
			kept = append(kept, k)
		}
	}
	return writeAuthorizedKeys(path, kept)
}

func writeAuthorizedKeys(path string, keys []string) error {
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o600)
}

// ---- fail2ban exec 实现 ----

type execFail2ban struct{}

// NewFail2ban 返回基于 fail2ban-client 的真实实现。
func NewFail2ban() Fail2ban { return execFail2ban{} }

func (execFail2ban) Available() error {
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		return fmt.Errorf("security: fail2ban-client not found")
	}
	return nil
}

func (execFail2ban) Status(jail string) (string, error) {
	args := []string{"status"}
	if jail != "" {
		args = append(args, "--", jail)
	}
	out, err := exec.Command("fail2ban-client", args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("fail2ban status: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func (execFail2ban) Banned(jail string) ([]string, error) {
	out, err := exec.Command("fail2ban-client", "status", "--", jail).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("fail2ban status %s: %w: %s", jail, err, strings.TrimSpace(string(out)))
	}
	return parseBannedIPs(string(out)), nil
}

func (execFail2ban) Unban(jail, ip string) error {
	out, err := exec.Command("fail2ban-client", "set", "--", jail, "unbanip", ip).CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban unban: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (execFail2ban) SetJail(jail string, enable bool) error {
	verb := "stop"
	if enable {
		verb = "start"
	}
	out, err := exec.Command("fail2ban-client", verb, "--", jail).CombinedOutput()
	if err != nil {
		return fmt.Errorf("fail2ban %s %s: %w: %s", verb, jail, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// parseBannedIPs 从 fail2ban-client status <jail> 输出里抽 "Banned IP list:" 行。
func parseBannedIPs(out string) []string {
	for _, line := range strings.Split(out, "\n") {
		idx := strings.Index(line, "Banned IP list:")
		if idx < 0 {
			continue
		}
		rest := strings.TrimSpace(line[idx+len("Banned IP list:"):])
		if rest == "" {
			return nil
		}
		ips := strings.Fields(rest)
		sort.Strings(ips)
		return ips
	}
	return nil
}

// ---- 登录日志 exec 实现 ----

type execLoginLog struct{}

// NewLoginLog 返回基于 last/lastb 的真实实现。
func NewLoginLog() LoginLog { return execLoginLog{} }

func (execLoginLog) Recent(failed bool, limit int) ([]LoginEntry, error) {
	bin := "last"
	if failed {
		bin = "lastb"
	}
	out, err := exec.Command(bin, "-i", "-n", strconv.Itoa(limit)).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s: %w: %s", bin, err, strings.TrimSpace(string(out)))
	}
	return parseLastOutput(string(out), failed), nil
}

// parseLastOutput 解析 last/lastb 输出。每行形如:
// "user  pts/0  1.2.3.4  Mon Jun 15 10:00 ...";尾部 wtmp/btmp/reboot 行跳过。
func parseLastOutput(out string, failed bool) []LoginEntry {
	var entries []LoginEntry
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		if fields[0] == "wtmp" || fields[0] == "btmp" || fields[0] == "reboot" {
			continue
		}
		when := ""
		if len(fields) >= 7 {
			when = strings.Join(fields[3:7], " ")
		}
		entries = append(entries, LoginEntry{
			User:   fields[0],
			IP:     fields[2],
			When:   when,
			Failed: failed,
		})
	}
	return entries
}
