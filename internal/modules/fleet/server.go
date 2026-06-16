//go:build fleet

package fleet

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
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

// 内嵌 NATS 鉴权用户名。controller 自连用 userController(全权);
// 引导连接用 userBootstrap(只能 enroll);节点连接用其 nodeID 作用户名(最小权限)。
const (
	userController = "__controller"
	userBootstrap  = "__bootstrap"
)

// controller 持有内嵌 NATS server 与一条自连客户端,处理 enroll/heartbeat 并下发命令。
type controller struct {
	ss         *fleetStore
	bootSecret string // 引导凭证密码(受限:只能 enroll,不能订阅任何 fleet.cmd.*)
	ctlPass    string // controller 自连密码(进程内随机,全权)

	mu   sync.Mutex
	ns   *natsserver.Server
	nc   *nats.Conn
	subs []*nats.Subscription
}

func newController(ss *fleetStore, bootSecret string) *controller {
	return &controller{ss: ss, bootSecret: bootSecret, ctlPass: randToken()}
}

// fleetAuth 是内嵌 NATS 的自定义鉴权回调:按用户名+密码判定身份并赋最小 subject 权限。
// controller 全权;bootstrap 仅能 enroll;节点仅能订自身 cmd、心跳自身、回复 inbox。
type fleetAuth struct{ c *controller }

func (a fleetAuth) Check(client natsserver.ClientAuthentication) bool {
	opts := client.GetOpts()
	user, pass := opts.Username, opts.Password

	switch user {
	case userController:
		if pass != a.c.ctlPass {
			return false
		}
		client.RegisterUser(&natsserver.User{Username: user}) // nil Permissions = 全权
		return true

	case userBootstrap:
		if pass != a.c.bootSecret {
			return false
		}
		// 引导凭证:只能 request fleet.enroll(publish 主题 + 回自己的 inbox),不能订阅任何 cmd。
		client.RegisterUser(&natsserver.User{
			Username: user,
			Permissions: &natsserver.Permissions{
				Publish:   &natsserver.SubjectPermission{Allow: []string{subjEnroll, "_INBOX.>"}},
				Subscribe: &natsserver.SubjectPermission{Allow: []string{"_INBOX.>"}},
			},
		})
		return true

	default:
		// 节点凭证:用户名=nodeID,密码须与存表的专属密码一致,且节点仍存在。
		if !validNodeID(user) {
			return false
		}
		want, ok, err := a.c.ss.nodeCred(user)
		if err != nil || !ok || pass != want {
			return false
		}
		client.RegisterUser(&natsserver.User{
			Username: user,
			Permissions: &natsserver.Permissions{
				// 只能订自己的命令主题;publish 限于自身心跳 + 回复 inbox(Respond)。
				Subscribe: &natsserver.SubjectPermission{Allow: []string{cmdSubject(user)}},
				Publish:   &natsserver.SubjectPermission{Allow: []string{hbSubject(user), "_INBOX.>"}},
			},
		})
		return true
	}
}

// start 进程内起 NATS 并订阅 enroll/heartbeat。快速返回:不阻塞调用方。
func (c *controller) start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ns != nil {
		return nil
	}
	opts := &natsserver.Options{
		Host:   defaultHost,
		Port:   defaultPort,
		NoLog:  true,
		NoSigs: true, // 不抢宿主进程的信号处理
		// per-connection subject ACL:由 fleetAuth 按用户名赋最小权限,取代全舰队共用 token。
		CustomClientAuthentication: fleetAuth{c: c},
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
	nc, err := nats.Connect(ns.ClientURL(),
		nats.UserInfo(userController, c.ctlPass), nats.Name("fleet-controller"))
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
	hbSub, err := nc.Subscribe(subjHeartbeat+".*", c.handleHeartbeat)
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

// handleEnroll 处理引导连接的入网/取凭证请求(两步):
//  1. 首次:校验 token(未消费且未绑他人)→ 绑定到该 nodeID → 注册 pending → 回 Approved:false。
//  2. 审批后再次轮询:节点已 active 且已签发专属凭证 → 消费 token(真正一次性)→ 回专属凭证。
func (c *controller) handleEnroll(m *nats.Msg) {
	var req enrollMsg
	if err := json.Unmarshal(m.Data, &req); err != nil {
		c.replyEnrollErr(m, "bad request")
		return
	}
	if !validNodeID(req.NodeID) {
		c.replyEnrollErr(m, "invalid node id")
		return
	}
	bound, err := c.ss.bindEnrollToken(req.Token, req.NodeID)
	if err != nil {
		log.Printf("fleet: bind token: %v", err)
		c.replyEnrollErr(m, "internal error")
		return
	}
	if !bound {
		c.replyEnrollErr(m, "invalid or used token")
		return
	}
	if err := c.ss.upsertNode(Node{
		ID: req.NodeID, Name: req.Name, Tags: req.Tags, Version: req.Version,
	}); err != nil {
		log.Printf("fleet: upsert node: %v", err)
		c.replyEnrollErr(m, "internal error")
		return
	}

	node, err := c.ss.getNode(req.NodeID)
	if err != nil {
		log.Printf("fleet: get node: %v", err)
		c.replyEnrollErr(m, "internal error")
		return
	}
	pass, ok, err := c.ss.nodeCred(req.NodeID)
	if err != nil {
		log.Printf("fleet: node cred: %v", err)
		c.replyEnrollErr(m, "internal error")
		return
	}
	if node.Status != nodeActive || !ok {
		c.reply(m, enrollReply{OK: true, Approved: false}) // 仍待审批,agent 继续轮询
		return
	}
	if err := c.ss.consumeEnrollToken(req.Token, req.NodeID); err != nil {
		log.Printf("fleet: consume token: %v", err)
	}
	c.reply(m, enrollReply{OK: true, Approved: true, NodeUser: req.NodeID, NodePass: pass})
}

func (c *controller) replyEnrollErr(m *nats.Msg, errMsg string) {
	c.reply(m, enrollReply{OK: false, Error: errMsg})
}

func (c *controller) reply(m *nats.Msg, rep enrollReply) {
	if m.Reply == "" {
		return
	}
	b, _ := json.Marshal(rep)
	_ = m.Respond(b)
}

// handleHeartbeat 更新 last_seen。node_id 取自 subject(fleet.hb.<nodeID>)=鉴权身份,
// 不信 payload:节点只能 publish fleet.hb.<自身>,故无法伪造他人心跳。
func (c *controller) handleHeartbeat(m *nats.Msg) {
	nodeID := strings.TrimPrefix(m.Subject, subjHBPrefix)
	if nodeID == "" || nodeID == m.Subject {
		return
	}
	if err := c.ss.touchNode(nodeID, time.Now().Unix()); err != nil {
		log.Printf("fleet: touch node: %v", err)
	}
}

// approveNode 审批节点并签发专属凭证(随机密码,存表)。审批后 agent 轮询 enroll 即可取得。
func (c *controller) approveNode(nodeID string) error {
	if err := c.ss.setNodeCred(nodeID, randToken()); err != nil {
		return err
	}
	return c.ss.approveNode(nodeID)
}

// deleteNode 删除节点、撤销专属凭证,并主动断开其在途连接(凭证立即失效)。
func (c *controller) deleteNode(nodeID string) error {
	if err := c.ss.deleteNode(nodeID); err != nil {
		return err
	}
	c.evictClient(nodeID)
	return nil
}

// evictClient 断开以某 nodeID(用户名)鉴权的所有在途客户端连接。
func (c *controller) evictClient(nodeID string) {
	c.mu.Lock()
	ns := c.ns
	c.mu.Unlock()
	if ns == nil {
		return
	}
	cz, err := ns.Connz(&natsserver.ConnzOptions{Username: true, User: nodeID})
	if err != nil {
		log.Printf("fleet: connz: %v", err)
		return
	}
	for _, ci := range cz.Conns {
		if ci.AuthorizedUser == nodeID {
			_ = ns.DisconnectClientByID(ci.Cid)
		}
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
