package service

import (
	"context"
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
}

// Module 是可开关的服务管理模块:封装 systemctl 启停查。
type Module struct{ deps Deps }

func New(deps Deps) *Module { return &Module{deps: deps} }

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
	r.Get("/status", m.handleStatus)                     // 只读:任意已认证角色
	r.Post("/{verb:start|stop|restart}", m.handleAction) // 写:需 operator+
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

func (m *Module) handleAction(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return
	}
	unit := r.URL.Query().Get("unit")
	if !system.ValidUnitName(unit) {
		http.Error(w, "invalid unit name", http.StatusBadRequest)
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	out, err := system.ServiceAction(verb, unit)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "service."+verb, unit+" "+outcome, clientIP(r))
	if err != nil {
		log.Printf("service: %s for %q failed: %v", verb, unit, err)
		http.Error(w, "service operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// clientIP 从 RemoteAddr 取 IP(无代理信任,与 server 层一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
