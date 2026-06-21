package service

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入模块对宿主能力的依赖,避免直接耦合 server/store 包。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的服务管理模块:封装 systemctl 启停查。
type Module struct {
	deps   Deps
	runner commandRunner // 默认走真实 systemctl;测试注入样本
	// action 执行状态变更动词,默认 system.ServiceAction;测试注入 stub 以避免真实 exec。
	action func(verb, unit string) (string, error)
}

func New(deps Deps) *Module {
	return &Module{deps: deps, runner: systemctlRunner{}, action: system.ServiceAction}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "service", Name: "服务管理", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "服务管理", Icon: "server-cog", Path: "/service"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:systemctl 不在则不允许启用。
func (*Module) HealthCheck() error { return system.SystemctlAvailable() }

func (m *Module) Routes(r module.Router) {
	r.Get("/status", m.handleStatus)                                           // 只读:任意已认证角色
	r.Get("/services", m.handleListServices)                                   // 只读:列出系统服务
	r.Post("/{verb:start|stop|restart|reload|enable|disable}", m.handleAction) // 写:需 admin + 确认头
}

func (m *Module) handleListServices(w http.ResponseWriter, _ *http.Request) {
	services, err := listServices(m.runner)
	if err != nil {
		log.Printf("service: list services failed: %v", err)
		http.Error(w, "services unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(services)
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	if !system.ValidUnitName(unit) {
		http.Error(w, "invalid unit name", http.StatusBadRequest)
		return
	}
	out, err := system.ServiceAction("status", unit)
	if err != nil {
		log.Printf("service: status for %q failed: %v", unit, err)
		http.Error(w, "status unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// handleAction 执行状态变更动词。校验顺序:
// ValidUnitName -> admin -> X-Confirm-Danger -> unit 在服务列表内 -> 执行 -> 审计。
func (m *Module) handleAction(w http.ResponseWriter, r *http.Request) {
	unit := r.URL.Query().Get("unit")
	if !system.ValidUnitName(unit) {
		http.Error(w, "invalid unit name", http.StatusBadRequest)
		return
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	if r.Header.Get("X-Confirm-Danger") == "" {
		http.Error(w, "missing X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	if !m.unitInList(unit) {
		http.Error(w, "unknown unit", http.StatusBadRequest)
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	out, err := m.action(verb, unit)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "service."+verb, unit+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("service: %s for %q failed: %v", verb, unit, err)
		http.Error(w, "service operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// unitInList 判断 unit 是否在当前服务列表中,作为白名单约束。列举失败时拒绝。
func (m *Module) unitInList(unit string) bool {
	services, err := listServices(m.runner)
	if err != nil {
		return false
	}
	for i := range services {
		if services[i].Name == unit {
			return true
		}
	}
	return false
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
