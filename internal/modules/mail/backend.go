package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
)

// mailBackend 抽象底层 postfix/dovecot 的虚拟域/邮箱/别名落盘与服务 reload。
// 口令经此接口传递但绝不落 XPanel 的库:由后端用 doveadm pw 哈希写入 dovecot 用户库。
// 环境多半未装 postfix/dovecot,故接口便于 mock 测试。
//
// 实现把 XPanel 的库(权威数据源)整体投影成配置文件:每次域/邮箱/别名变更后,
// 模块用最新全量数据调用 sync* 方法重写对应 map 文件并 postmap + reload。
type mailBackend interface {
	// available 报告后端可用(postfix 在 PATH),供模块 HealthCheck。
	available() error
	// hashPassword 用 dovecot 的 doveadm pw 把明文口令哈希成 dovecot 用户库可用格式。
	hashPassword(ctx context.Context, password string) (string, error)
	// syncDomains 重写虚拟域文件并 postmap。
	syncDomains(ctx context.Context, s Settings, domains []string) error
	// syncMailboxes 重写虚拟邮箱 map 文件并 postmap,同时重写 dovecot 用户库(passdb)。
	// users 的 PasswordHash 为 dovecot 格式哈希(已 hashPassword),绝非明文。
	syncMailboxes(ctx context.Context, s Settings, boxes []mailboxUser) error
	// syncAliases 重写虚拟别名 map 文件并 postmap。
	syncAliases(ctx context.Context, s Settings, aliases []aliasMeta) error
	// reload 重载 postfix/dovecot 使新 map 生效。
	reload(ctx context.Context) error
}

// mailboxUser 是 dovecot 用户库一行所需:地址 + maildir + 配额 + 已哈希口令。
type mailboxUser struct {
	Address      string
	Maildir      string
	QuotaMB      int64
	PasswordHash string // dovecot 格式哈希,绝非明文
}

// postfixDovecot 用 postmap 落 postfix map、用 doveadm pw 哈希口令、写 dovecot passwd-file
// 用户库,改后 reload postfix+dovecot。所有外部命令走参数数组,口令仅经 stdin 交给
// doveadm,绝不进 argv、命令行或日志。
type postfixDovecot struct {
	postfix string // postfix 路径(reload 用)
	postmap string // postmap 路径(重建 .db map)
	doveadm string // doveadm 路径(pw 哈希 + reload)
}

// newPostfixDovecot 解析命令路径。找不到 postfix 则后端不可用,但仍返回实例供 available 报错。
func newPostfixDovecot() *postfixDovecot {
	pf, _ := exec.LookPath("postfix")
	pm, _ := exec.LookPath("postmap")
	da, _ := exec.LookPath("doveadm")
	return &postfixDovecot{postfix: pf, postmap: pm, doveadm: da}
}

func (b *postfixDovecot) available() error {
	if b.postfix == "" {
		return errors.New("postfix not found in PATH")
	}
	return nil
}

func (b *postfixDovecot) hashPassword(ctx context.Context, password string) (string, error) {
	if b.doveadm == "" {
		return "", errors.New("doveadm not found in PATH")
	}
	// doveadm pw -s SHA512-CRYPT -p <stdin>。口令经 stdin,不进 argv。
	cmd := exec.CommandContext(ctx, b.doveadm, "pw", "-s", "SHA512-CRYPT")
	cmd.Stdin = strings.NewReader(password + "\n" + password + "\n")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("doveadm pw: %w", err)
	}
	return strings.TrimSpace(buf.String()), nil
}

func (b *postfixDovecot) syncDomains(ctx context.Context, s Settings, domains []string) error {
	sort.Strings(domains)
	var lines []string
	for _, d := range domains {
		// postfix virtual_mailbox_domains map: "<domain> OK"
		lines = append(lines, d+"\tOK")
	}
	return b.writePostmap(ctx, s.VirtualDomainFile, lines)
}

func (b *postfixDovecot) syncMailboxes(ctx context.Context, s Settings, boxes []mailboxUser) error {
	sort.Slice(boxes, func(i, j int) bool { return boxes[i].Address < boxes[j].Address })
	var mboxLines, userLines []string
	for _, m := range boxes {
		// postfix virtual_mailbox_maps: "<addr> <maildir>"(maildir 相对 virtual_mailbox_base)
		mboxLines = append(mboxLines, m.Address+"\t"+m.Maildir)
		// dovecot passwd-file: "<addr>:<hash>::::::userdb_quota_rule=*:storage=<N>M"
		line := m.Address + ":" + m.PasswordHash + "::::::"
		if m.QuotaMB > 0 {
			line += fmt.Sprintf("userdb_quota_rule=*:storage=%dM", m.QuotaMB)
		}
		userLines = append(userLines, line)
	}
	if err := b.writePostmap(ctx, s.VirtualMailboxFile, mboxLines); err != nil {
		return err
	}
	// dovecot 用户库是纯文本(passwd-file),不需 postmap;原子落盘即可。
	return writeFileAtomic(s.DovecotConfigDir+"/users", strings.Join(userLines, "\n"), 0o640)
}

func (b *postfixDovecot) syncAliases(ctx context.Context, s Settings, aliases []aliasMeta) error {
	sort.Slice(aliases, func(i, j int) bool {
		if aliases[i].Source != aliases[j].Source {
			return aliases[i].Source < aliases[j].Source
		}
		return aliases[i].Destination < aliases[j].Destination
	})
	// postfix virtual_alias_maps 同一 source 多目标用逗号分隔在一行。
	merged := map[string][]string{}
	var order []string
	for _, a := range aliases {
		if _, ok := merged[a.Source]; !ok {
			order = append(order, a.Source)
		}
		merged[a.Source] = append(merged[a.Source], a.Destination)
	}
	var lines []string
	for _, src := range order {
		lines = append(lines, src+"\t"+strings.Join(merged[src], ","))
	}
	return b.writePostmap(ctx, s.VirtualAliasFile, lines)
}

func (b *postfixDovecot) reload(ctx context.Context) error {
	if err := b.available(); err != nil {
		return err
	}
	if _, err := b.run(ctx, b.postfix, "reload"); err != nil {
		return err
	}
	if b.doveadm != "" {
		if _, err := b.run(ctx, b.doveadm, "reload"); err != nil {
			return err
		}
	}
	return nil
}

// writePostmap 原子重写 map 源文件,再 postmap 重建 .db(若 postmap 可用)。
func (b *postfixDovecot) writePostmap(ctx context.Context, path string, lines []string) error {
	if err := writeFileAtomic(path, strings.Join(lines, "\n"), 0o644); err != nil {
		return err
	}
	if b.postmap == "" {
		return errors.New("postmap not found in PATH")
	}
	_, err := b.run(ctx, b.postmap, "hash:"+path)
	return err
}

// run 执行 name <args...>,绝不拼接 shell:参数数组直传。返回合并输出。
func (b *postfixDovecot) run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if err := cmd.Run(); err != nil {
		return buf.String(), fmt.Errorf("%s %v: %w", name, args, err)
	}
	return buf.String(), nil
}

// writeFileAtomic 把 content 原子写入 path(先写临时文件再 rename),避免 reload 读到半截。
func writeFileAtomic(path, content string, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
