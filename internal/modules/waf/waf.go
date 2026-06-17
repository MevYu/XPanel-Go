// Package waf 实现网站防火墙模块:IP 黑/白名单、URL/UA 规则、CC 防御(限速/限连),
// 全部通过生成 nginx 配置片段实现。任何写进配置的输入都经严格校验,
// 配置经 nginx -t 把关通过后才 reload。
package waf

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server/store 包。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的网站防火墙模块。
type Module struct {
	ws   *wafStore
	ng   Nginx
	deps Deps
}

// New 建表并返回模块。建表失败(DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, deps Deps) *Module {
	ws, err := newWAFStore(st)
	if err != nil {
		panic("waf: init store: " + err.Error())
	}
	return &Module{ws: ws, ng: NewNginx(), deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "waf", Name: "网站防火墙", Category: "安全"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "网站防火墙", Icon: "shield-alert", Path: "/waf"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:无 nginx 二进制则不允许启用。
func (m *Module) HealthCheck() error { return m.ng.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读:任意已认证角色
	r.Put("/settings", m.handlePutSettings) // 写:admin

	r.Get("/ip", m.handleListIP)                // 只读
	r.Post("/ip", m.handleCreateIP)             // 写:admin
	r.Delete("/ip/{id}", m.handleDeleteIP)      // 写:admin
	r.Post("/ip/{id}/toggle", m.handleToggleIP) // 写:admin,翻转单条 IP 规则启停

	r.Get("/match", m.handleListMatch)                // 只读
	r.Post("/match", m.handleCreateMatch)             // 写:admin
	r.Delete("/match/{id}", m.handleDeleteMatch)      // 写:admin
	r.Post("/match/{id}/toggle", m.handleToggleMatch) // 写:admin,翻转单条匹配规则启停

	r.Get("/cc", m.handleGetCC) // 只读
	r.Put("/cc", m.handlePutCC) // 写:admin

	r.Get("/config", m.handlePreviewConfig) // 只读:预览将生成的配置
	r.Get("/stats", m.handleStats)          // 只读:拦截统计
	r.Post("/apply", m.handleApply)         // 写:admin,重新生成配置 + nginx -t + reload
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

// --- Settings ---

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	s, err := m.ws.getSettings()
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
	// 关闭全局总开关 = 整体卸防护,属危险操作:需 X-Confirm-Danger。
	if !s.WAFEnabled {
		cur, err := m.ws.getSettings()
		if err != nil {
			serverError(w, "load settings", err)
			return
		}
		if cur.WAFEnabled && !confirmed(r) {
			http.Error(w, "disabling WAF requires X-Confirm-Danger header", http.StatusPreconditionRequired)
			return
		}
	}
	if err := m.ws.setSettings(s); err != nil {
		serverError(w, "save settings", err)
		return
	}
	m.deps.Audit(&uid, "waf.settings.update", "waf_enabled="+strconv.FormatBool(s.WAFEnabled), m.clientIP(r))
	writeJSON(w, http.StatusOK, s)
}

// --- IP rules ---

func (m *Module) handleListIP(w http.ResponseWriter, _ *http.Request) {
	rules, err := m.ws.listIP()
	if err != nil {
		serverError(w, "list ip", err)
		return
	}
	if rules == nil {
		rules = []IPRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (m *Module) handleCreateIP(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var rule IPRule
	if !decode(w, r, &rule) {
		return
	}
	// 严格校验:非法即拒,绝不入库、绝不进配置。
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := m.ws.createIP(rule)
	if err != nil {
		serverError(w, "create ip", err)
		return
	}
	m.deps.Audit(&uid, "waf.ip.create", rule.Action+" "+rule.CIDR, m.clientIP(r))
	rule.ID = id
	writeJSON(w, http.StatusCreated, rule)
}

func (m *Module) handleDeleteIP(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	n, err := m.ws.deleteIP(id)
	if err != nil {
		serverError(w, "delete ip", err)
		return
	}
	if n == 0 {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "waf.ip.delete", strconv.FormatInt(id, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleToggleIP(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body toggleBody
	if !decode(w, r, &body) {
		return
	}
	n, err := m.ws.setIPEnabled(id, body.Enabled)
	if err != nil {
		serverError(w, "toggle ip", err)
		return
	}
	if n == 0 {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "waf.ip.toggle", strconv.FormatInt(id, 10)+" enabled="+strconv.FormatBool(body.Enabled), m.clientIP(r))
	writeJSON(w, http.StatusOK, body)
}

// --- Match rules ---

func (m *Module) handleListMatch(w http.ResponseWriter, _ *http.Request) {
	rules, err := m.ws.listMatch()
	if err != nil {
		serverError(w, "list match", err)
		return
	}
	if rules == nil {
		rules = []MatchRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (m *Module) handleCreateMatch(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var rule MatchRule
	if !decode(w, r, &rule) {
		return
	}
	if err := rule.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	id, err := m.ws.createMatch(rule)
	if err != nil {
		serverError(w, "create match", err)
		return
	}
	m.deps.Audit(&uid, "waf.match.create", rule.Target+" "+rule.Action, m.clientIP(r))
	rule.ID = id
	writeJSON(w, http.StatusCreated, rule)
}

func (m *Module) handleDeleteMatch(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	n, err := m.ws.deleteMatch(id)
	if err != nil {
		serverError(w, "delete match", err)
		return
	}
	if n == 0 {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "waf.match.delete", strconv.FormatInt(id, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleToggleMatch(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body toggleBody
	if !decode(w, r, &body) {
		return
	}
	n, err := m.ws.setMatchEnabled(id, body.Enabled)
	if err != nil {
		serverError(w, "toggle match", err)
		return
	}
	if n == 0 {
		http.Error(w, "rule not found", http.StatusNotFound)
		return
	}
	m.deps.Audit(&uid, "waf.match.toggle", strconv.FormatInt(id, 10)+" enabled="+strconv.FormatBool(body.Enabled), m.clientIP(r))
	writeJSON(w, http.StatusOK, body)
}

// --- CC ---

func (m *Module) handleGetCC(w http.ResponseWriter, _ *http.Request) {
	cc, err := m.ws.getCC()
	if err != nil {
		serverError(w, "get cc", err)
		return
	}
	writeJSON(w, http.StatusOK, cc)
}

func (m *Module) handlePutCC(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var cc CCConfig
	if !decode(w, r, &cc) {
		return
	}
	if err := cc.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ws.setCC(cc); err != nil {
		serverError(w, "save cc", err)
		return
	}
	m.deps.Audit(&uid, "waf.cc.update", "enabled="+strconv.FormatBool(cc.Enabled), m.clientIP(r))
	writeJSON(w, http.StatusOK, cc)
}

// --- Config preview / apply / stats ---

// loadRuleSet 从库里组装当前规则集,GlobalEnabled 取自 settings.waf_enabled。
func (m *Module) loadRuleSet() (RuleSet, error) {
	set, err := m.ws.getSettings()
	if err != nil {
		return RuleSet{}, err
	}
	ip, err := m.ws.listIP()
	if err != nil {
		return RuleSet{}, err
	}
	match, err := m.ws.listMatch()
	if err != nil {
		return RuleSet{}, err
	}
	cc, err := m.ws.getCC()
	if err != nil {
		return RuleSet{}, err
	}
	return RuleSet{GlobalEnabled: set.WAFEnabled, IPRules: ip, MatchRules: match, CC: cc}, nil
}

func (m *Module) handlePreviewConfig(w http.ResponseWriter, _ *http.Request) {
	rs, err := m.loadRuleSet()
	if err != nil {
		serverError(w, "load rules", err)
		return
	}
	cfg, err := GenerateConfig(rs)
	if err != nil {
		serverError(w, "generate config", err)
		return
	}
	writeJSON(w, http.StatusOK, cfg)
}

func (m *Module) handleApply(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	set, err := m.ws.getSettings()
	if err != nil {
		serverError(w, "load settings", err)
		return
	}
	rs, err := m.loadRuleSet()
	if err != nil {
		serverError(w, "load rules", err)
		return
	}
	out, err := applier{ng: m.ng}.apply(set, rs)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "waf.apply", outcome, m.clientIP(r))
	if err != nil {
		log.Printf("waf: apply failed: %v", err)
		// 把 nginx 输出回传给调用方排障(已通过 admin 鉴权)。
		http.Error(w, "apply failed: "+out, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (m *Module) handleStats(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ws.getSettings()
	if err != nil {
		serverError(w, "load settings", err)
		return
	}
	stats, err := ReadStats(set.LogPath)
	if err != nil {
		log.Printf("waf: read stats failed: %v", err)
		http.Error(w, "stats unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, stats)
}

// --- helpers ---

// toggleBody 是单规则启停端点的请求体/响应体。
type toggleBody struct {
	Enabled bool `json:"enabled"`
}

// confirmed 报告危险操作确认头是否存在。
func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	raw := chi.URLParamFromCtx(r.Context(), "id")
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

func serverError(w http.ResponseWriter, what string, err error) {
	log.Printf("waf: %s failed: %v", what, err)
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
