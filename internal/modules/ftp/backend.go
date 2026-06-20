package ftp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// account 是一个 FTP 虚拟用户的非敏感视图(绝不含口令)。
type account struct {
	User string `json:"user"`
	Home string `json:"home"`
}

// ftpBackend 抽象底层 FTP 服务的用户库操作。口令经此接口传递但绝不落 XPanel 的库,
// 由后端(pure-ftpd 的 .pdb)自行哈希存储。环境可能无 FTP 服务,故接口便于 mock 测试。
type ftpBackend interface {
	// list 返回所有虚拟用户(不含口令)。
	list(ctx context.Context) ([]account, error)
	// create 新建虚拟用户。readonly 为真则只授读权限。quotaMB 为存储配额(MB),0=不限。
	create(ctx context.Context, user, password, home string, readonly bool, quotaMB int) error
	// delete 删除虚拟用户。
	delete(ctx context.Context, user string) error
	// setPassword 改虚拟用户口令。
	setPassword(ctx context.Context, user, password string) error
	// setQuota 设置虚拟用户存储配额(MB),0=不限。
	setQuota(ctx context.Context, user string, quotaMB int) error
	// setEnabled 启停虚拟用户(pure-ftpd 用账户过期/激活实现)。
	setEnabled(ctx context.Context, user string, enabled bool) error
	// available 报告后端可用(命令存在),供模块 HealthCheck。
	available() error
}

// pureFTPd 用 pure-pw 管理虚拟用户库,改后 mkdb 重建 .pdb。
// 口令经 stdin 交给 pure-pw,绝不进 exec 参数、命令行或日志。
type pureFTPd struct {
	purePW string // pure-pw 路径
	pureDB string // pure-pw 落库后重建 .pdb 用(mkdb)
	uid    string // 虚拟用户映射到的系统 uid(-u)
	gid    string // 虚拟用户映射到的系统 gid(-g)
}

// newPureFTPd 解析 pure-pw 路径。找不到则后端不可用,但仍返回实例供 available 报错。
func newPureFTPd(uid, gid string) *pureFTPd {
	p, _ := exec.LookPath("pure-pw")
	return &pureFTPd{purePW: p, pureDB: p, uid: uid, gid: gid}
}

func (b *pureFTPd) available() error {
	if b.purePW == "" {
		return errors.New("pure-pw not found in PATH")
	}
	return nil
}

func (b *pureFTPd) list(ctx context.Context) ([]account, error) {
	if err := b.available(); err != nil {
		return nil, err
	}
	out, err := b.run(ctx, "", "list")
	if err != nil {
		return nil, err
	}
	var accts []account
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// pure-pw list 输出: "<user>\t<home>/./"
		fields := strings.Fields(line)
		a := account{User: fields[0]}
		if len(fields) > 1 {
			a.Home = strings.TrimSuffix(fields[1], "/./")
		}
		accts = append(accts, a)
	}
	return accts, nil
}

func (b *pureFTPd) create(ctx context.Context, user, password, home string, _ bool, quotaMB int) error {
	if err := b.available(); err != nil {
		return err
	}
	// -m 立即重建 .pdb;口令经 stdin(pure-pw 提示两次)。
	// 注:pure-pw 的 -r 是"限定允许的来源 IP",并非只读权限;旧代码 `-r ""` 既不实现
	// 只读又传了无意义空参。pure-pw useradd 无逐用户只读开关(只读由 pure-ftpd 守护层
	// 配置),故此处不据 readonly 传任何参数;只读意图仅落 XPanel 的账户元数据。
	args := []string{"useradd", user, "-u", b.uid, "-g", b.gid, "-d", home}
	// -N <MB> 设存储配额;0=不限,故仅 >0 时传(配额为校验过的 int,作为独立 argv 元素)。
	if quotaMB > 0 {
		args = append(args, "-N", strconv.Itoa(quotaMB))
	}
	args = append(args, "-m")
	if _, err := b.run(ctx, passwordStdin(password), args...); err != nil {
		return err
	}
	return nil
}

func (b *pureFTPd) setQuota(ctx context.Context, user string, quotaMB int) error {
	if err := b.available(); err != nil {
		return err
	}
	// -N <MB> 设存储配额(0=不限);-m 立即重建 .pdb。配额为校验过的 int,作为独立 argv 元素。
	_, err := b.run(ctx, "", "usermod", user, "-N", strconv.Itoa(quotaMB), "-m")
	return err
}

func (b *pureFTPd) delete(ctx context.Context, user string) error {
	if err := b.available(); err != nil {
		return err
	}
	_, err := b.run(ctx, "", "userdel", user, "-m")
	return err
}

func (b *pureFTPd) setPassword(ctx context.Context, user, password string) error {
	if err := b.available(); err != nil {
		return err
	}
	_, err := b.run(ctx, passwordStdin(password), "passwd", user, "-m")
	return err
}

func (b *pureFTPd) setEnabled(ctx context.Context, user string, enabled bool) error {
	if err := b.available(); err != nil {
		return err
	}
	// pure-pw usermod -r/-w 不停账户;用 -y(0=禁用登录,1=允许)实现启停。
	flag := "0"
	if enabled {
		flag = "1"
	}
	_, err := b.run(ctx, "", "usermod", user, "-y", flag, "-m")
	return err
}

// run 执行 pure-pw <args...>,口令(若有)经 stdin 传入。返回合并输出。
// 绝不拼接 shell:参数数组直传,口令不进 argv。
func (b *pureFTPd) run(ctx context.Context, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, b.purePW, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	if err := cmd.Run(); err != nil {
		return buf.String(), fmt.Errorf("pure-pw %s: %w", args[0], err)
	}
	return buf.String(), nil
}

// passwordStdin 构造 pure-pw 交互口令输入:同一口令两次(确认),各以换行结尾。
func passwordStdin(password string) string {
	return password + "\n" + password + "\n"
}
