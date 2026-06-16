//go:build fleet

package fleet

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

const agentVersion = "0.0.1"
const heartbeatInterval = 15 * time.Second

// maxCmdOutput 截断单条命令输出上限,防超大输出撑爆 agent 内存与 controller DB。
const maxCmdOutput = 1 << 20 // 1 MiB

// enrollPollInterval 是审批前轮询 enroll 取专属凭证的间隔。
const enrollPollInterval = 3 * time.Second

// RunAgent 以 agent 模式运行,两段式入网:
//  1. 用受限引导凭证(username=__bootstrap, password=secret)连入,仅能 request fleet.enroll;
//     enroll 后轮询直至 admin 审批并下发专属凭证(username=nodeID, password=随机)。
//  2. 关引导连接,用专属凭证重连,订阅自身命令主题并周期心跳,直至中断信号。阻塞。
//
// controllerAddr 形如 "host:port" 或完整 nats:// URL;token 为 controller 下发的
// 不透明凭证 `<enroll>.<bootstrapSecret>`。
func RunAgent(controllerAddr, token, name, tags string) error {
	enrollTok, bootSecret, ok := splitToken(token)
	if !ok {
		return fmt.Errorf("fleet agent: malformed token (want <enroll>.<secret>)")
	}
	url := normalizeURL(controllerAddr)
	nodeID, err := stableNodeID()
	if err != nil {
		return err
	}
	if name == "" {
		name, _ = os.Hostname()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// 阶段 1:引导连接 + enroll 轮询取专属凭证。
	user, pass, err := enrollAndAwaitCred(ctx, url, enrollTok, nodeID, name, tags, bootSecret)
	if err != nil {
		return err
	}

	// 阶段 2:用专属凭证重连。
	nc, err := nats.Connect(url, nats.UserInfo(user, pass), nats.Name("fleet-agent:"+nodeID),
		nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return fmt.Errorf("fleet agent: reconnect: %w", err)
	}
	defer nc.Close()

	a := &agent{nc: nc, nodeID: nodeID}
	sub, err := nc.Subscribe(cmdSubject(nodeID), a.handleCmd)
	if err != nil {
		return fmt.Errorf("fleet agent: subscribe: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	a.heartbeatLoop(ctx)
	return nil
}

// enrollAndAwaitCred 用引导凭证连入,轮询 enroll 直至审批通过,返回专属 (user, pass)。
func enrollAndAwaitCred(ctx context.Context, url, token, nodeID, name, tags, bootSecret string) (string, string, error) {
	nc, err := nats.Connect(url, nats.UserInfo(userBootstrap, bootSecret), nats.Name("fleet-bootstrap:"+nodeID))
	if err != nil {
		return "", "", fmt.Errorf("fleet agent: bootstrap connect %s: %w", url, err)
	}
	defer nc.Close()

	b, _ := json.Marshal(enrollMsg{
		Token: token, NodeID: nodeID, Name: name, Tags: tags, Version: agentVersion,
	})
	for {
		msg, err := nc.Request(subjEnroll, b, 10*time.Second)
		if err != nil {
			return "", "", fmt.Errorf("fleet agent: enroll request: %w", err)
		}
		var rep enrollReply
		if err := json.Unmarshal(msg.Data, &rep); err != nil {
			return "", "", fmt.Errorf("fleet agent: enroll reply: %w", err)
		}
		if !rep.OK {
			return "", "", fmt.Errorf("fleet agent: enroll rejected: %s", rep.Error)
		}
		if rep.Approved {
			return rep.NodeUser, rep.NodePass, nil
		}
		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(enrollPollInterval):
		}
	}
}

type agent struct {
	nc     *nats.Conn
	nodeID string
}

func (a *agent) heartbeatLoop(ctx context.Context) {
	a.beat()
	t := time.NewTicker(heartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			a.beat()
		}
	}
}

func (a *agent) beat() {
	b, _ := json.Marshal(heartbeatMsg{NodeID: a.nodeID, Version: agentVersion})
	_ = a.nc.Publish(hbSubject(a.nodeID), b)
	_ = a.nc.Flush()
}

// handleCmd 执行 controller 下发的命令(参数数组,绝不拼 shell)并回传结果。
func (a *agent) handleCmd(m *nats.Msg) {
	var cmd cmdMsg
	if err := json.Unmarshal(m.Data, &cmd); err != nil || m.Reply == "" {
		return
	}
	rep := execArgv(cmd.Argv, cmd.TimeoutSec)
	b, _ := json.Marshal(rep)
	_ = m.Respond(b)
}

// execArgv 以参数数组执行命令,绝不经 shell。返回退出码、合并输出、耗时。
func execArgv(argv []string, timeoutSec int) cmdReply {
	if len(argv) == 0 {
		return cmdReply{Failed: true, Output: "empty command"}
	}
	timeout := time.Duration(timeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	start := time.Now()
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// 上限缓冲:输出超 maxCmdOutput 即截断,丢弃其余,防超大输出 OOM/撑爆 DB。
	var buf bytes.Buffer
	lw := &limitedWriter{w: &buf, n: maxCmdOutput}
	c.Stdout, c.Stderr = lw, lw
	err := c.Run()
	dur := time.Since(start).Milliseconds()

	out := buf.Bytes()
	if lw.truncated {
		out = append(out, "\n[output truncated]"...)
	}
	rep := cmdReply{Output: string(out), DurationMs: dur}
	if err == nil {
		rep.ExitCode = 0
		return rep
	}
	if ee, ok := err.(*exec.ExitError); ok {
		rep.ExitCode = ee.ExitCode() // 非 0 退出:命令失败但进程已执行
		return rep
	}
	rep.Failed = true // 进程无法启动 / 超时 kill
	rep.ExitCode = -1
	return rep
}

// limitedWriter 向 w 写至多 n 字节,超出部分丢弃并置 truncated;Write 永不报错(避免 exec 因
// 写失败提前终止子进程)。stdout/stderr 共用同一 writer 时 exec 用两个 goroutine 并发写,故加锁。
type limitedWriter struct {
	mu        sync.Mutex
	w         io.Writer
	n         int
	truncated bool
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.n > 0 {
		take := len(p)
		if take > l.n {
			take = l.n
		}
		_, _ = l.w.Write(p[:take])
		l.n -= take
	}
	if len(p) > 0 && l.n == 0 {
		l.truncated = true
	}
	return len(p), nil
}

// splitToken 拆 controller 凭证 `<enroll>.<natsSecret>`(secret 自身可含 base64url 的 '-'/'_',不含 '.')。
func splitToken(token string) (enroll, secret string, ok bool) {
	i := strings.IndexByte(token, '.')
	if i <= 0 || i == len(token)-1 {
		return "", "", false
	}
	return token[:i], token[i+1:], true
}

// normalizeURL 把 "host:port" 补成 nats:// URL;已带 scheme 则原样。
func normalizeURL(addr string) string {
	if strings.Contains(addr, "://") {
		return addr
	}
	if !strings.Contains(addr, ":") {
		addr = fmt.Sprintf("%s:%d", addr, defaultPort)
	}
	return "nats://" + addr
}

// stableNodeID 返回机器稳定 ID:优先 /etc/machine-id,否则随机一次。
func stableNodeID() (string, error) {
	if b, err := os.ReadFile("/etc/machine-id"); err == nil {
		if id := strings.TrimSpace(string(b)); id != "" {
			return id, nil
		}
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("fleet agent: node id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
