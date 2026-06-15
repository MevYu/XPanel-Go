// Package alert 实现监控告警模块:阈值规则 + 通知渠道(邮件/Webhook/Telegram),
// 后台周期评估系统指标,触发则按静默期去重后发通知并记历史。
// 渠道凭证 AES-GCM 加密落库,绝不明文返回或进日志。元数据存自建表,不动中央 migrations。
package alert

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的监控告警模块。
type Module struct {
	ss   *alertStore
	deps Deps

	mu     sync.Mutex      // 守护 cancel/wg(Start/Stop 可被 Manager 串行调用)
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New 建表并返回模块。secret 用于派生渠道凭证的 AES-GCM 密钥。
// 建表/派生失败直接 panic:模块无法工作。
func New(secret string, st *store.Store, deps Deps) *Module {
	cryp, err := newCryptor(secret)
	if err != nil {
		panic("alert: init cryptor: " + err.Error())
	}
	ss, err := newAlertStore(st, cryp)
	if err != nil {
		panic("alert: init store: " + err.Error())
	}
	return &Module{ss: ss, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "alert", Name: "监控告警", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "监控告警", Icon: "bell-ring", Path: "/alert"}}
}

// HealthCheck:本模块只读 system 指标,无外部依赖,总是可用。
func (*Module) HealthCheck() error { return nil }

// Start 起后台评估 goroutine。迅速返回:真实评估在 detached goroutine 里跑。
func (m *Module) Start(context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return nil // 已在运行
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.wg.Add(1)
	go m.runLoop(ctx)
	return nil
}

// Stop 干净停止后台 goroutine 并等待退出。
func (m *Module) Stop(context.Context) error {
	m.mu.Lock()
	cancel := m.cancel
	m.cancel = nil
	m.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	m.wg.Wait()
	return nil
}

// runLoop 周期评估,直到 ctx 取消。评估间隔从设置读取(支持运行时调整)。
func (m *Module) runLoop(ctx context.Context) {
	defer m.wg.Done()
	ev := newEvaluator(m.ss)
	for {
		set, err := m.ss.loadSettings()
		if err != nil {
			set = DefaultSettings()
		}
		if _, err := ev.evaluateOnce(ctx); err != nil {
			log.Printf("alert: evaluate failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(set.IntervalSec) * time.Second):
		}
	}
}

func (m *Module) Routes(r module.Router) {
	r.Get("/rules", m.handleListRules)             // 只读
	r.Post("/rules", m.handleCreateRule)           // 写:operator+
	r.Put("/rules/{id}", m.handleUpdateRule)       // 写:operator+
	r.Delete("/rules/{id}", m.handleDeleteRule)    // 写:operator+

	r.Get("/channels", m.handleListChannels)       // 只读(凭证已屏蔽)
	r.Post("/channels", m.handleCreateChannel)     // 写:admin(凭证)
	r.Put("/channels/{id}", m.handleUpdateChannel) // 写:admin(凭证)
	r.Delete("/channels/{id}", m.handleDeleteChannel) // 写:admin
	r.Post("/channels/{id}/test", m.handleTestChannel) // 测试发送:admin

	r.Get("/history", m.handleListHistory) // 只读

	r.Get("/settings", m.handleGetSettings) // 只读
	r.Put("/settings", m.handlePutSettings) // 写:admin
}

// ---- rules ----

type ruleRequest struct {
	Name        string  `json:"name"`
	Metric      string  `json:"metric"`
	Comparator  string  `json:"comparator"`
	Threshold   float64 `json:"threshold"`
	DurationSec int     `json:"duration_sec"`
	ChannelID   int64   `json:"channel_id"`
	Enabled     bool    `json:"enabled"`
}

func (m *Module) handleListRules(w http.ResponseWriter, _ *http.Request) {
	rs, err := m.ss.listRules()
	if err != nil {
		log.Printf("alert: list rules failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if rs == nil {
		rs = []Rule{}
	}
	writeJSON(w, http.StatusOK, rs)
}

func (m *Module) handleCreateRule(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req ruleRequest
	if !decode(w, r, &req) {
		return
	}
	rule := Rule{
		Name: req.Name, Metric: req.Metric, Comparator: req.Comparator,
		Threshold: req.Threshold, DurationSec: req.DurationSec,
		ChannelID: req.ChannelID, Enabled: req.Enabled,
	}
	if err := validateRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.ss.getChannel(rule.ChannelID); err != nil {
		http.Error(w, "channel not found", http.StatusBadRequest)
		return
	}
	id, err := m.ss.createRule(rule)
	if err != nil {
		log.Printf("alert: create rule failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "alert.rule.create", rule.Name, clientIP(r))
	out, _ := m.ss.getRule(id)
	writeJSON(w, http.StatusCreated, out)
}

func (m *Module) handleUpdateRule(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req ruleRequest
	if !decode(w, r, &req) {
		return
	}
	rule := Rule{
		ID: id, Name: req.Name, Metric: req.Metric, Comparator: req.Comparator,
		Threshold: req.Threshold, DurationSec: req.DurationSec,
		ChannelID: req.ChannelID, Enabled: req.Enabled,
	}
	if err := validateRule(rule); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.ss.getChannel(rule.ChannelID); err != nil {
		http.Error(w, "channel not found", http.StatusBadRequest)
		return
	}
	if err := m.ss.updateRule(rule); err != nil {
		if err == errNotFound {
			http.Error(w, "rule not found", http.StatusNotFound)
			return
		}
		log.Printf("alert: update rule failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "alert.rule.update", rule.Name, clientIP(r))
	out, _ := m.ss.getRule(id)
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleDeleteRule(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := m.ss.deleteRule(id); err != nil {
		log.Printf("alert: delete rule failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "alert.rule.delete", strconv.FormatInt(id, 10), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// ---- channels ----

func (m *Module) handleListChannels(w http.ResponseWriter, _ *http.Request) {
	cs, err := m.ss.listChannels()
	if err != nil {
		log.Printf("alert: list channels failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if cs == nil {
		cs = []Channel{}
	}
	writeJSON(w, http.StatusOK, cs)
}

func (m *Module) handleCreateChannel(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var c Channel
	if !decode(w, r, &c) {
		return
	}
	if !validChannelKind(c.Kind) || c.Name == "" {
		http.Error(w, "invalid channel: name and known kind required", http.StatusBadRequest)
		return
	}
	id, err := m.ss.createChannel(c)
	if err != nil {
		log.Printf("alert: create channel failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	// 审计不含凭证:只记名称与类型。
	m.deps.Audit(&uid, "alert.channel.create", c.Name+" ("+string(c.Kind)+")", clientIP(r))
	out, _ := m.ss.getChannel(id)
	writeJSON(w, http.StatusCreated, out)
}

func (m *Module) handleUpdateChannel(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var c Channel
	if !decode(w, r, &c) {
		return
	}
	c.ID = id
	if !validChannelKind(c.Kind) || c.Name == "" {
		http.Error(w, "invalid channel: name and known kind required", http.StatusBadRequest)
		return
	}
	if err := m.ss.updateChannel(c); err != nil {
		if err == errNotFound {
			http.Error(w, "channel not found", http.StatusNotFound)
			return
		}
		log.Printf("alert: update channel failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "alert.channel.update", c.Name+" ("+string(c.Kind)+")", clientIP(r))
	out, _ := m.ss.getChannel(id)
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleDeleteChannel(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := m.ss.deleteChannel(id); err != nil {
		log.Printf("alert: delete channel failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "alert.channel.delete", strconv.FormatInt(id, 10), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// handleTestChannel 向渠道发一条测试通知(用已存的加密凭证),验证配置是否可达。
func (m *Module) handleTestChannel(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ch, secret, err := m.ss.getChannelEnc(id)
	if err != nil {
		if err == errNotFound {
			http.Error(w, "channel not found", http.StatusNotFound)
			return
		}
		http.Error(w, "test failed", http.StatusInternalServerError)
		return
	}
	sender, err := senderFor(ch.Kind)
	if err != nil {
		http.Error(w, "unknown channel kind", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	n := Notification{Subject: "[XPanel 告警] 测试通知", Body: "这是一条来自 XPanel 监控告警模块的测试消息。"}
	sendErr := sender.Send(ctx, ch, secret, n)
	outcome := "ok"
	if sendErr != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "alert.channel.test", ch.Name+" "+outcome, clientIP(r))
	if sendErr != nil {
		// 不回显底层错误明细:可能含凭证片段。
		log.Printf("alert: test channel %d failed: %v", id, sendErr)
		http.Error(w, "test send failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"result": "sent"})
}

// ---- history & settings ----

func (m *Module) handleListHistory(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	hs, err := m.ss.listHistory(limit)
	if err != nil {
		log.Printf("alert: list history failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if hs == nil {
		hs = []History{}
	}
	writeJSON(w, http.StatusOK, hs)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("alert: load settings failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var set Settings
	if !decode(w, r, &set) {
		return
	}
	if err := set.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ss.saveSettings(set); err != nil {
		log.Printf("alert: save settings failed: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "alert.settings", "interval="+itoa(set.IntervalSec)+" silence="+itoa(set.SilenceSec), clientIP(r))
	writeJSON(w, http.StatusOK, set)
}

// ---- helpers ----

func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(v); err != nil {
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

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// clientIP 从 RemoteAddr 取 IP(无代理信任,与 server 层一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
