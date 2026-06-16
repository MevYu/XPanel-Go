package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入模块对宿主能力的依赖,避免直接耦合 server/store 包。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的防火墙管理模块:抽象 ufw/firewalld 后端,管端口/IP/ping/状态。
type Module struct {
	deps Deps

	// 测试可替换的间接层;生产用 execRunner + detectBackend。
	run        runner
	newBackend func(runner) Backend
	sshConfig  string
}

func New(deps Deps) *Module {
	return &Module{
		deps:       deps,
		run:        execRunner{},
		newBackend: detectBackend,
		sshConfig:  defaultSSHConfig,
	}
}

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
	r.Get("/status", m.handleStatus)    // 只读:状态总览(后端/运行态/规则数/SSH端口)
	r.Get("/backend", m.handleBackend)  // 只读:检测到的后端
	r.Get("/ssh", m.handleSSH)          // 只读:SSH 端口(仅展示)
	r.Get("/rules", m.handleListRules)  // 只读:结构化端口规则
	r.Post("/rules", m.handleAddRule)   // 写:放行/拒绝端口或端口段,需 admin
	r.Delete("/rules", m.handleDelRule) // 危险写:删除端口规则,需 admin + 二次确认
	r.Post("/ip", m.handleAddIP)        // 写:封禁/信任 IP,需 admin(封禁=危险)
	r.Delete("/ip", m.handleDelIP)      // 危险写:移除黑白名单条目,需 admin + 二次确认
	r.Post("/ping", m.handlePing)       // 写:允许/禁止 ping,需 admin(禁止=危险)
	r.Post("/enable", m.handleEnable)   // 写:启用防火墙,需 admin
	r.Post("/disable", m.handleDisable) // 危险写:禁用防火墙,需 admin + 二次确认
}

// backend 取后端;无可用后端返回 nil。
func (m *Module) backend() Backend { return m.newBackend(m.run) }

// ---- 只读端点 ----

func (m *Module) handleStatus(w http.ResponseWriter, _ *http.Request) {
	b := m.backend()
	if b == nil {
		st := Status{SSHPort: readSSHPort(m.sshConfig)}
		writeJSON(w, http.StatusOK, st)
		return
	}
	st, err := b.Status()
	if err != nil {
		// 状态查询失败仍回部分信息(后端类型已知),不 500 阻断面板。
		log.Printf("firewall: status failed: %v", err)
	}
	st.SSHPort = readSSHPort(m.sshConfig)
	writeJSON(w, http.StatusOK, st)
}

func (m *Module) handleBackend(w http.ResponseWriter, _ *http.Request) {
	name := ""
	if b := m.backend(); b != nil {
		name = b.Name()
	}
	writeJSON(w, http.StatusOK, map[string]string{"backend": name})
}

func (m *Module) handleSSH(w http.ResponseWriter, _ *http.Request) {
	// 只读展示:真正改 sshd 端口留给 security 模块,避免锁死;此处提示放行新端口的做法。
	writeJSON(w, http.StatusOK, map[string]any{
		"port":     readSSHPort(m.sshConfig),
		"readonly": true,
		"note":     "修改 SSH 端口需在 security 模块操作;请先用本模块放行新端口再切换,避免锁死",
	})
}

func (m *Module) handleListRules(w http.ResponseWriter, _ *http.Request) {
	b := m.backend()
	if b == nil {
		writeJSON(w, http.StatusOK, []PortRule{})
		return
	}
	rules, err := b.ListPortRules()
	if err != nil {
		log.Printf("firewall: list failed: %v", err)
		http.Error(w, "firewall unavailable", http.StatusInternalServerError)
		return
	}
	if rules == nil {
		rules = []PortRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

// ---- 端口规则写端点 ----

func (m *Module) handleAddRule(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var rule PortRule
	if !decode(w, r, &rule) {
		return
	}
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.applyPort(w, r, uid, rule, true, "firewall.rule.add")
}

// handleDelRule 删除端口规则属危险操作:需二次确认。
func (m *Module) handleDelRule(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var rule PortRule
	if !decode(w, r, &rule) {
		return
	}
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.applyPort(w, r, uid, rule, false, "firewall.rule.del")
}

func (m *Module) applyPort(w http.ResponseWriter, r *http.Request, uid int64, rule PortRule, add bool, action string) {
	b := m.backend()
	if b == nil {
		http.Error(w, "firewall unavailable", http.StatusInternalServerError)
		return
	}
	out, err := b.ApplyPortRule(rule, add)
	m.audit(uid, action, rule.Action+"/"+rule.Proto+"/"+rule.Port+" "+outcome(err), r)
	m.writeResult(w, out, err)
}

// ---- IP 黑白名单 ----

func (m *Module) handleAddIP(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var rule IPRule
	if !decode(w, r, &rule) {
		return
	}
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 封禁 IP 属危险操作:需二次确认。信任 IP 仅需 admin。
	if rule.Action == IPBlock && !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	m.applyIP(w, r, uid, rule, true, "firewall.ip.add")
}

// handleDelIP 移除黑白名单条目属危险操作(可能解除封禁):需二次确认。
func (m *Module) handleDelIP(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var rule IPRule
	if !decode(w, r, &rule) {
		return
	}
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	m.applyIP(w, r, uid, rule, false, "firewall.ip.del")
}

func (m *Module) applyIP(w http.ResponseWriter, r *http.Request, uid int64, rule IPRule, add bool, action string) {
	b := m.backend()
	if b == nil {
		http.Error(w, "firewall unavailable", http.StatusInternalServerError)
		return
	}
	out, err := b.ApplyIPRule(rule, add)
	m.audit(uid, action, string(rule.Action)+"/"+rule.IP+" "+outcome(err), r)
	m.writeResult(w, out, err)
}

// ---- Ping 开关 ----

func (m *Module) handlePing(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var body struct {
		Allow bool `json:"allow"`
	}
	if !decode(w, r, &body) {
		return
	}
	// 禁止 ping 属危险操作:需二次确认。
	if !body.Allow && !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	b := m.backend()
	if b == nil {
		http.Error(w, "firewall unavailable", http.StatusInternalServerError)
		return
	}
	out, err := b.SetPing(body.Allow)
	if errors.Is(err, errPingUnsupported) {
		http.Error(w, "ping toggle not supported by this backend", http.StatusNotImplemented)
		return
	}
	verb := "ping.allow"
	if !body.Allow {
		verb = "ping.deny"
	}
	m.audit(uid, "firewall."+verb, outcome(err), r)
	m.writeResult(w, out, err)
}

// ---- 启停防火墙 ----

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
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	b := m.backend()
	if b == nil {
		http.Error(w, "firewall unavailable", http.StatusInternalServerError)
		return
	}
	out, err := b.SetEnabled(enable)
	action := "firewall.enable"
	if !enable {
		action = "firewall.disable"
	}
	m.audit(uid, action, outcome(err), r)
	m.writeResult(w, out, err)
}

// ---- 公共辅助 ----

// requireAdmin 校验 admin 角色;非 admin 写 403 返回 ok=false(不审计)。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// decode 解析受限大小的 JSON 请求体;失败写 400 返回 false。
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(v); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return false
	}
	return true
}

func (m *Module) audit(uid int64, action, detail string, r *http.Request) {
	m.deps.Audit(&uid, action, detail, m.clientIP(r))
}

// writeResult 输出命令文本,或将失败转 500(失败已在前面审计)。
func (m *Module) writeResult(w http.ResponseWriter, out string, err error) {
	if err != nil {
		log.Printf("firewall: operation failed: %v", err)
		http.Error(w, "firewall operation failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func outcome(err error) string {
	if err != nil {
		return "failed"
	}
	return "ok"
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
