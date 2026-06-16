//go:build fleet

package fleet

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
)

const agentVersion = "0.0.1"
const heartbeatInterval = 15 * time.Second

// RunAgent 以 agent 模式运行:连入 controller 的 NATS,用一次性 token 入网,
// 订阅自己的命令主题并周期心跳,直至收到中断信号。阻塞,供 cmd 的 agent 入口调用。
//
// controllerAddr 形如 "host:port" 或完整 nats:// URL;token 为 controller 下发的
// 不透明凭证 `<enroll>.<natsSecret>`:enroll 部分一次性入网,natsSecret 部分做 NATS 连接鉴权。
func RunAgent(controllerAddr, token, name, tags string) error {
	enrollTok, natsSecret, ok := splitToken(token)
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

	nc, err := nats.Connect(url, nats.Token(natsSecret), nats.Name("fleet-agent:"+nodeID),
		nats.MaxReconnects(-1), nats.ReconnectWait(2*time.Second))
	if err != nil {
		return fmt.Errorf("fleet agent: connect %s: %w", url, err)
	}
	defer nc.Close()

	a := &agent{nc: nc, nodeID: nodeID}
	if err := a.enroll(enrollTok, name, tags); err != nil {
		return err
	}
	sub, err := nc.Subscribe(cmdSubject(nodeID), a.handleCmd)
	if err != nil {
		return fmt.Errorf("fleet agent: subscribe: %w", err)
	}
	defer func() { _ = sub.Unsubscribe() }()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	a.heartbeatLoop(ctx)
	return nil
}

type agent struct {
	nc     *nats.Conn
	nodeID string
}

func (a *agent) enroll(token, name, tags string) error {
	b, _ := json.Marshal(enrollMsg{
		Token: token, NodeID: a.nodeID, Name: name, Tags: tags, Version: agentVersion,
	})
	msg, err := a.nc.Request(subjEnroll, b, 10*time.Second)
	if err != nil {
		return fmt.Errorf("fleet agent: enroll request: %w", err)
	}
	var rep enrollReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		return fmt.Errorf("fleet agent: enroll reply: %w", err)
	}
	if !rep.OK {
		return fmt.Errorf("fleet agent: enroll rejected: %s", rep.Error)
	}
	return nil
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
	_ = a.nc.Publish(subjHeartbeat, b)
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
	out, err := c.CombinedOutput()
	dur := time.Since(start).Milliseconds()

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
