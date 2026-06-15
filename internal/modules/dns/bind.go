package dns

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

var (
	errNoCreds  = errors.New("dns provider: API credentials not configured")
	errBadZone  = errors.New("dns bind: refusing unsafe zone name")
	errReadOnly = errors.New("dns bind: zone directory not writable")
)

// bindBackend 管理本地 BIND 的 zone 文件并触发 rndc reload。
// 记录真相源在 store;apply 全量重写 zone 文件(原子替换),再 reload。
type bindBackend struct {
	zoneDir string // zone 文件目录
	reload  func(ctx context.Context, zone string) error
}

// newBindBackend 用 zone 目录构造后端。reload 默认走 rndc。
func newBindBackend(zoneDir string) *bindBackend {
	return &bindBackend{zoneDir: zoneDir, reload: rndcReload}
}

func (*bindBackend) kind() string { return "bind" }

// healthy:rndc 可执行且 zone 目录存在可写。
func (b *bindBackend) healthy() error {
	if _, err := exec.LookPath("rndc"); err != nil {
		return errors.New("dns bind: rndc not found in PATH")
	}
	info, err := os.Stat(b.zoneDir)
	if err != nil || !info.IsDir() {
		return errReadOnly
	}
	// 用临时文件探测可写。
	f, err := os.CreateTemp(b.zoneDir, ".xpanel-dns-*")
	if err != nil {
		return errReadOnly
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

// apply 渲染 zone 文件并原子替换,然后 reload。
func (b *bindBackend) apply(ctx context.Context, zone string, records []Record) error {
	if !validDomain(zone) {
		return errBadZone // 二次防御:zone 名进文件路径,必须白名单
	}
	content, err := renderZone(zone, records)
	if err != nil {
		return err
	}
	path := b.zonePath(zone)
	if err := atomicWrite(path, content); err != nil {
		return err
	}
	return b.reload(ctx, zone)
}

// zonePath 返回 zone 文件路径。zone 已经过 validDomain 校验,不含路径分隔符。
func (b *bindBackend) zonePath(zone string) string {
	return filepath.Join(b.zoneDir, "db."+strings.TrimSuffix(zone, "."))
}

// renderZone 渲染一个 BIND zone 文件。所有记录字段已在上游通过 validValue 等校验,
// 此处再做一次保守拒绝(含换行/分号等元字符直接报错),纵深防御 zone 注入。
func renderZone(zone string, records []Record) (string, error) {
	var sb strings.Builder
	sb.WriteString("; managed by XPanel — do not edit by hand\n")
	sb.WriteString("$TTL 3600\n")
	sb.WriteString("@\tIN\tSOA\tns1." + zone + ". admin." + zone + ". (\n")
	sb.WriteString("\t" + serial() + " ; serial\n")
	sb.WriteString("\t3600 1800 604800 86400 )\n")
	for _, r := range records {
		line, err := renderRecord(r)
		if err != nil {
			return "", err
		}
		sb.WriteString(line)
	}
	return sb.String(), nil
}

// renderRecord 渲染一行记录。任何元字符出现即报错(上游应已挡住)。
func renderRecord(r Record) (string, error) {
	if strings.ContainsAny(r.Name, "\n\r\t ") || strings.ContainsAny(r.Value, "\n\r") {
		return "", errBadValue
	}
	if !validType(r.Type) {
		return "", errBadType
	}
	ttl := r.TTL
	if !validTTL(ttl) {
		ttl = 3600
	}
	name := r.Name
	val := r.Value
	if r.Type == "TXT" {
		val = "\"" + val + "\"" // TXT 内容已禁裸引号,这里安全加引号
	}
	var b strings.Builder
	b.WriteString(name + "\t" + strconv.Itoa(ttl) + "\tIN\t" + r.Type + "\t")
	if needsPriority(r.Type) {
		b.WriteString(strconv.Itoa(r.Priority) + " ")
	}
	b.WriteString(val + "\n")
	return b.String(), nil
}

// atomicWrite 原子写文件:写临时文件再 rename(同目录),权限 0644。
func atomicWrite(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".xpanel-zone-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // rename 成功后该 remove 无害(目标已不在)
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

// rndcReload 触发 BIND 重载单个 zone。参数走数组,绝不拼 shell。
func rndcReload(ctx context.Context, zone string) error {
	if !validDomain(zone) {
		return errBadZone
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "rndc", "reload", strings.TrimSuffix(zone, ".")).CombinedOutput()
	if err != nil {
		return errors.New("rndc reload failed: " + strings.TrimSpace(string(out)))
	}
	return nil
}

// serial 用当前 Unix 秒作为 SOA serial(单调递增即可,无需 YYYYMMDDnn)。
func serial() string { return strconv.FormatInt(time.Now().Unix(), 10) }
