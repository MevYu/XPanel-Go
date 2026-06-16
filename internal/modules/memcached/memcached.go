// Package memcached 实现 Memcached 缓存管理模块:经文本协议读 stats/slabs、
// 经 systemctl 启停服务、flush_all 清空缓存(危险)。设置存自建表,不动中央 migrations。
package memcached

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的 Memcached 缓存管理模块。
type Module struct {
	ms     *mcStore
	client Client
	deps   Deps
}

// New 建表并返回模块。建表失败(DB 不可用)直接 panic:模块无法工作。
// client 为 nil 时用默认的 net 实现。
func New(st *store.Store, client Client, deps Deps) *Module {
	ms, err := newMCStore(st)
	if err != nil {
		panic("memcached: init store: " + err.Error())
	}
	if client == nil {
		client = NewClient()
	}
	return &Module{ms: ms, client: client, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "memcached", Name: "Memcached", Category: "数据库"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "Memcached", Icon: "zap", Path: "/memcached"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:能连上配置的 memcached 地址才允许启用。
func (m *Module) HealthCheck() error {
	set, err := m.ms.getSettings()
	if err != nil {
		return err
	}
	_, err = m.client.Stats(set.Addr)
	return err
}

func (m *Module) Routes(r module.Router) {
	r.Get("/stats", m.handleStats)          // 只读:任意已认证角色
	r.Get("/slabs", m.handleSlabs)          // 只读
	r.Get("/settings", m.handleGetSettings) // 只读
	r.Put("/settings", m.handlePutSettings) // 写:admin

	r.Post("/{verb:start|stop|restart}", m.handleAction) // 写:admin,systemctl 启停
	r.Post("/flush", m.handleFlush)                      // 危险:admin + X-Confirm-Danger + 审计
}

// requireAdmin 校验 admin 角色。失败时已写 403,返回 ok=false。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// --- Stats / Slabs ---

func (m *Module) handleStats(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ms.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	raw, err := m.client.Stats(set.Addr)
	if err != nil {
		connError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, buildStats(raw))
}

func (m *Module) handleSlabs(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ms.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	slabs, err := m.client.Slabs(set.Addr)
	if err != nil {
		connError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, slabs)
}

// --- Settings ---

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	s, err := m.ms.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var s Settings
	if !decode(w, r, &s) {
		return
	}
	if err := s.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ms.setSettings(s); err != nil {
		serverError(w, "save settings", err)
		return
	}
	m.deps.Audit(&uid, "memcached.settings.update", s.Addr, m.clientIP(r))
	writeJSON(w, http.StatusOK, s)
}

// --- Service action ---

func (m *Module) handleAction(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	set, err := m.ms.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	out, err := system.ServiceAction(verb, set.ServiceUnit)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "memcached."+verb, set.ServiceUnit+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("memcached: %s for %q failed: %v", verb, set.ServiceUnit, err)
		http.Error(w, "service operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// --- flush_all (危险) ---

func (m *Module) handleFlush(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	set, err := m.ms.getSettings()
	if err != nil {
		serverError(w, "settings", err)
		return
	}
	err = m.client.FlushAll(set.Addr)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "memcached.flush_all", set.Addr+" "+outcome, m.clientIP(r))
	if err != nil {
		connError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// --- helpers ---

func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

// connError:连不上 memcached 属外部依赖故障,不泄底层细节给客户端。
func connError(w http.ResponseWriter, err error) {
	log.Printf("memcached: connection failed: %v", err)
	http.Error(w, "memcached unavailable", http.StatusBadGateway)
}

func serverError(w http.ResponseWriter, what string, err error) {
	log.Printf("memcached: %s failed: %v", what, err)
	http.Error(w, what+" failed", http.StatusInternalServerError)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 取真实客户端 IP:有受信代理感知的提取器则用之,否则回退 RemoteAddr。
func (m *Module) clientIP(r *http.Request) string {
	if m.deps.ClientIP != nil {
		return m.deps.ClientIP(r)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
