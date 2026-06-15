package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/coder/websocket"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/system"
)

const (
	ticketTTL   = 30 * time.Second // 票据有效期:够前端拿到后立即连 WS
	idleTimeout = 15 * time.Minute // 空闲超时:无输出/输入则断会话
	wsReadLimit = 1 << 20          // 单条 WS 消息上限 1MiB,挡超大帧
)

// Deps 注入模块对宿主能力的依赖,避免直接耦合 server/store 包。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是 Web 终端模块:短时票据换取 WS,WS 桥接到 PTY 里的 shell。
type Module struct {
	deps    Deps
	tickets *ticketStore
}

func New(deps Deps) *Module {
	return &Module{deps: deps, tickets: newTicketStore(ticketTTL, time.Now)}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "terminal", Name: "Web 终端", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "Web 终端", Icon: "terminal", Path: "/terminal"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无可用 shell 则不允许启用。
func (*Module) HealthCheck() error { return system.ShellAvailable() }

func (m *Module) Routes(r module.Router) {
	r.Post("/ticket", m.handleTicket) // 走面板认证:operator+ 换一张短时票据
}

// PublicPrefix 把 WS 端点挂在面板认证之外:浏览器原生 WS 不能带 Authorization 头,
// WS 仅凭 ?ticket= 自鉴权。
func (*Module) PublicPrefix() string { return "/api/m/terminal/ws" }

// PublicRoutes 返回 WS handler;MountPublic 在停用模块时已经 enable-gate 成 404。
func (m *Module) PublicRoutes() http.Handler {
	return http.HandlerFunc(m.handleWS)
}

// handleTicket 校验角色后签发短时一次性票据。前端拿到后立即去连 /ws?ticket=。
func (m *Module) handleTicket(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return
	}
	tok := m.tickets.issue(uid, role)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"ticket": tok})
}

// handleWS 校验票据 → 升级 WS → 起 PTY → 双向桥接。票据无效/过期/已用一律拒绝。
func (m *Module) handleWS(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("ticket")
	sess, ok := m.tickets.consume(tok)
	if !ok {
		http.Error(w, "invalid or expired ticket", http.StatusUnauthorized)
		return
	}

	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(wsReadLimit)

	ip := clientIP(r)
	uid := sess.userID
	m.deps.Audit(&uid, "terminal.open", "session start", ip)
	defer m.deps.Audit(&uid, "terminal.close", "session end", ip)

	if err := bridge(c); err != nil {
		log.Printf("terminal: session for uid=%d from %s ended: %v", uid, ip, err)
	}
}

// wsMsg 是前端→后端的控制/数据帧。Type=data 时 Data 为按键输入;
// Type=resize 时 Rows/Cols 为新窗口尺寸。
type wsMsg struct {
	Type string `json:"type"`
	Data string `json:"data"`
	Rows uint16 `json:"rows"`
	Cols uint16 `json:"cols"`
}

// bridge 起一个 PTY 并在 WS 与 PTY 间双向搬运字节,直到任一端断开或空闲超时。
func bridge(c *websocket.Conn) error {
	pt, err := system.StartPTY()
	if err != nil {
		c.Close(websocket.StatusInternalError, "pty start failed")
		return err
	}
	defer pt.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer c.Close(websocket.StatusNormalClosure, "")

	idle := time.NewTimer(idleTimeout)
	defer idle.Stop()
	resetIdle := func() { idle.Reset(idleTimeout) }

	// PTY → WS:shell 输出推给浏览器。PTY EOF(shell 退出)即结束。
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := pt.Pty.Read(buf)
			if n > 0 {
				resetIdle()
				wctx, wcancel := context.WithTimeout(ctx, 10*time.Second)
				werr := c.Write(wctx, websocket.MessageBinary, buf[:n])
				wcancel()
				if werr != nil {
					cancel()
					return
				}
			}
			if err != nil {
				cancel()
				return
			}
		}
	}()

	// 空闲看门狗:超时主动断开。
	go func() {
		select {
		case <-ctx.Done():
		case <-idle.C:
			cancel()
		}
	}()

	// WS → PTY:浏览器输入与 resize 指令。读循环退出即会话结束。
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return wsReadErr(err)
		}
		resetIdle()
		if typ == websocket.MessageBinary {
			if _, werr := pt.Pty.Write(data); werr != nil {
				return werr
			}
			continue
		}
		var msg wsMsg
		if err := json.Unmarshal(data, &msg); err != nil {
			continue // 忽略无法解析的控制帧,不杀会话
		}
		switch msg.Type {
		case "data":
			if _, werr := pt.Pty.Write([]byte(msg.Data)); werr != nil {
				return werr
			}
		case "resize":
			_ = pt.Resize(msg.Rows, msg.Cols)
		}
	}
}

// wsReadErr 把正常关闭归一成 nil,其余作为真实错误返回。
func wsReadErr(err error) error {
	status := websocket.CloseStatus(err)
	if status == websocket.StatusNormalClosure || status == websocket.StatusGoingAway {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

// clientIP 从 RemoteAddr 取 IP(无代理信任,与 server 层一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
