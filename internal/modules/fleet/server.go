//go:build fleet

package fleet

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

// 默认绑内网回环,不公网暴露。
const (
	defaultHost = "127.0.0.1"
	defaultPort = 4223
)

// controller 持有内嵌 NATS server 与一条自连客户端,处理 enroll/heartbeat 并下发命令。
type controller struct {
	ss    *fleetStore
	token string // NATS 连接 token(全 agent 共用,MVP 鉴权;mTLS 为后续)

	mu   sync.Mutex
	ns   *natsserver.Server
	nc   *nats.Conn
	subs []*nats.Subscription
}

func newController(ss *fleetStore, token string) *controller {
	return &controller{ss: ss, token: token}
}

// start 进程内起 NATS 并订阅 enroll/heartbeat。快速返回:不阻塞调用方。
func (c *controller) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ns != nil {
		return nil
	}
	opts := &natsserver.Options{
		Host:          defaultHost,
		Port:          defaultPort,
		Authorization: c.token,
		NoLog:         true,
		NoSigs:        true, // 不抢宿主进程的信号处理
	}
	ns, err := natsserver.NewServer(opts)
	if err != nil {
		return fmt.Errorf("fleet: nats server: %w", err)
	}
	go ns.Start()
	if !ns.ReadyForConnections(5 * time.Second) {
		ns.Shutdown()
		return fmt.Errorf("fleet: nats server not ready")
	}
	nc, err := nats.Connect(ns.ClientURL(), nats.Token(c.token), nats.Name("fleet-controller"))
	if err != nil {
		ns.Shutdown()
		return fmt.Errorf("fleet: controller connect: %w", err)
	}
	c.ns, c.nc = ns, nc

	enrollSub, err := nc.Subscribe(subjEnroll, c.handleEnroll)
	if err != nil {
		c.shutdownLocked()
		return err
	}
	hbSub, err := nc.Subscribe(subjHeartbeat, c.handleHeartbeat)
	if err != nil {
		c.shutdownLocked()
		return err
	}
	c.subs = []*nats.Subscription{enrollSub, hbSub}
	return nil
}

func (c *controller) stop() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shutdownLocked()
}

func (c *controller) shutdownLocked() {
	for _, s := range c.subs {
		_ = s.Unsubscribe()
	}
	c.subs = nil
	if c.nc != nil {
		c.nc.Close()
		c.nc = nil
	}
	if c.ns != nil {
		c.ns.Shutdown()
		c.ns = nil
	}
}

// clientURL 暴露给测试用的模拟 agent。
func (c *controller) clientURL() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ns == nil {
		return ""
	}
	return c.ns.ClientURL()
}

// handleEnroll 校验一次性 token 并注册节点(status=pending,待 admin 审批)。
func (c *controller) handleEnroll(m *nats.Msg) {
	var req enrollMsg
	if err := json.Unmarshal(m.Data, &req); err != nil {
		c.replyEnroll(m, false, "bad request")
		return
	}
	ok, err := c.ss.consumeEnrollToken(req.Token)
	if err != nil {
		log.Printf("fleet: consume token: %v", err)
		c.replyEnroll(m, false, "internal error")
		return
	}
	if !ok {
		c.replyEnroll(m, false, "invalid or used token")
		return
	}
	if req.NodeID == "" {
		c.replyEnroll(m, false, "missing node id")
		return
	}
	if err := c.ss.upsertNode(Node{
		ID: req.NodeID, Name: req.Name, Tags: req.Tags, Version: req.Version,
	}); err != nil {
		log.Printf("fleet: upsert node: %v", err)
		c.replyEnroll(m, false, "internal error")
		return
	}
	c.replyEnroll(m, true, "")
}

func (c *controller) replyEnroll(m *nats.Msg, ok bool, errMsg string) {
	if m.Reply == "" {
		return
	}
	b, _ := json.Marshal(enrollReply{OK: ok, Error: errMsg})
	_ = m.Respond(b)
}

// handleHeartbeat 更新 last_seen。未审批节点也可上报,但不影响其零权限。
func (c *controller) handleHeartbeat(m *nats.Msg) {
	var hb heartbeatMsg
	if err := json.Unmarshal(m.Data, &hb); err != nil || hb.NodeID == "" {
		return
	}
	if err := c.ss.touchNode(hb.NodeID, time.Now().Unix()); err != nil {
		log.Printf("fleet: touch node: %v", err)
	}
}

// dispatch 向单个目标节点 NATS-request 下发命令,timeout 内无回复视为超时。
func (c *controller) dispatch(nodeID string, cmd cmdMsg, timeout time.Duration) (cmdReply, bool) {
	c.mu.Lock()
	nc := c.nc
	c.mu.Unlock()
	if nc == nil {
		return cmdReply{}, false
	}
	b, _ := json.Marshal(cmd)
	msg, err := nc.Request(cmdSubject(nodeID), b, timeout)
	if err != nil {
		return cmdReply{}, false // 含 nats.ErrTimeout / no responders
	}
	var rep cmdReply
	if err := json.Unmarshal(msg.Data, &rep); err != nil {
		return cmdReply{}, false
	}
	return rep, true
}
