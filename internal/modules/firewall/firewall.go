package firewall

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入模块对宿主能力的依赖,避免直接耦合 server/store 包。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的防火墙管理模块:抽象 ufw/firewalld 后端,管端口规则与启停。
type Module struct{ deps Deps }

func New(deps Deps) *Module { return &Module{deps: deps} }

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "firewall", Name: "防火墙", Category: "安全"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "防火墙", Icon: "shield", Path: "/firewall"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无 ufw/firewalld 后端则不允许启用。
func (*Module) HealthCheck() error { return system.FirewallAvailable() }

func (m *Module) Routes(r module.Router) {
	r.Get("/backend", m.handleBackend)  // 只读:返回检测到的后端
	r.Get("/rules", m.handleList)       // 只读:列出规则
	r.Post("/rules", m.handleAddRule)   // 写:放行/拒绝端口,需 admin
	r.Delete("/rules", m.handleDelRule) // 危险写:删除规则,需 admin + 二次确认
	r.Post("/enable", m.handleEnable)   // 写:启用防火墙,需 admin
	r.Post("/disable", m.handleDisable) // 危险写:禁用防火墙,需 admin + 二次确认
}

func (m *Module) handleBackend(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"backend": string(system.DetectBackend())})
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	out, err := system.ListRules()
	if err != nil {
		log.Printf("firewall: list failed: %v", err)
		http.Error(w, "firewall unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (m *Module) handleAddRule(w http.ResponseWriter, r *http.Request) {
	m.applyRule(w, r, true, "firewall.rule.add")
}

// handleDelRule 删除规则属危险操作:需二次确认。
func (m *Module) handleDelRule(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	m.applyRule(w, r, false, "firewall.rule.del")
}

func (m *Module) applyRule(w http.ResponseWriter, r *http.Request, add bool, action string) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var rule system.FirewallRule
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&rule); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	// 严格校验:非法即拒,绝不进命令行(无审计、无 exec)。
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	out, err := system.ApplyRule(rule, add)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, action, rule.Action+"/"+rule.Proto+"/"+strconv.Itoa(rule.Port)+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("firewall: apply rule failed: %v", err)
		http.Error(w, "firewall operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (m *Module) handleEnable(w http.ResponseWriter, r *http.Request) {
	m.setEnabled(w, r, true, false)
}

// handleDisable 禁用防火墙会清空保护,属危险操作:需二次确认。
func (m *Module) handleDisable(w http.ResponseWriter, r *http.Request) {
	m.setEnabled(w, r, false, true)
}

func (m *Module) setEnabled(w http.ResponseWriter, r *http.Request, enable, danger bool) {
	if danger && !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	out, err := system.SetEnabled(enable)
	action := "firewall.enable"
	if !enable {
		action = "firewall.disable"
	}
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, action, outcome, m.clientIP(r))
	if err != nil {
		log.Printf("firewall: set enabled=%v failed: %v", enable, err)
		http.Error(w, "firewall operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

// confirmed 检查危险操作的二次确认标记(API 层语义)。
func confirmed(r *http.Request) bool {
	return r.Header.Get("X-Confirm-Danger") != ""
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
