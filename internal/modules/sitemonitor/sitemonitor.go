package sitemonitor

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server/store 包。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的网站监控/访问分析模块:既只读解析 nginx 访问日志并聚合统计,
// 也维护一组被监控目标,Start 时起后台循环对其做主动 HTTP 探测。
type Module struct {
	ms     *monitorStore
	reader LogReader
	deps   Deps
	prober *prober
}

// New 建表并返回模块。建表失败(DB 不可用)直接 panic:模块无法工作。
// reader 为 nil 时用默认的本地文件只读实现。探测器默认用带 SSRF 拦截的真实实现;
// 测试可在构造后替换 m.prober.probe 注入 mock(零真实网络)。
func New(st *store.Store, reader LogReader, deps Deps) *Module {
	ms, err := newMonitorStore(st)
	if err != nil {
		panic("sitemonitor: init store: " + err.Error())
	}
	if reader == nil {
		reader = FileLogReader{}
	}
	return &Module{ms: ms, reader: reader, deps: deps, prober: newProber(ms, safeProber{})}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "sitemonitor", Name: "网站监控", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "网站监控", Icon: "bar-chart-2", Path: "/sitemonitor"}}
}

// Start 起后台探测循环。必须快速返回:start 只 spawn goroutine 后即返回。
func (m *Module) Start(ctx context.Context) error { m.prober.start(ctx); return nil }

// Stop 取消探测循环并等待其退出。
func (m *Module) Stop(context.Context) error { m.prober.stop(); return nil }

// HealthCheck:纯 Go 只读分析,无外部二进制依赖,恒可用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读:任意已认证角色
	r.Put("/settings", m.handlePutSettings) // 写:admin

	r.Get("/overview", m.handleOverview) // 概览统计(总请求/带宽/状态码/UV/Top)
	r.Get("/sites", m.handleSites)       // 按站点统计
	r.Get("/trend", m.handleTrend)       // 时间趋势(hour/day)
	r.Get("/top", m.handleTop)           // Top 列表(url/ip/ua)

	r.Post("/snapshot", m.handleSnapshot) // 写:admin,落盘当前聚合快照

	// 主动探测目标 CRUD:列表只读;写操作 operator/admin;删除 admin + X-Confirm-Danger。
	r.Get("/targets", m.handleListTargets)
	r.Post("/targets", m.requireWrite(m.handleCreateTarget))
	r.Put("/targets/{id}", m.requireWrite(m.handleUpdateTarget))
	r.Delete("/targets/{id}", m.handleDeleteTarget) // 内部自查 admin + X-Confirm-Danger
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

// requireWrite 包一层 RBAC:仅 operator/admin 可进。
func (m *Module) requireWrite(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, role := m.deps.Principal(r); role != "admin" && role != "operator" {
			http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
			return
		}
		next(w, r)
	}
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
	m.deps.Audit(&uid, "sitemonitor.settings.update", s.AccessLog, m.clientIP(r))
	writeJSON(w, http.StatusOK, s)
}

// --- Analysis ---

// loadEntries 读取并解析日志(尾部受 MaxLines 限制),返回解析成功的记录与生效设置。
// 路径经 SafeJoin 限定在 LogRoot 子树内,挡穿越/软链逃逸。
func (m *Module) loadEntries(r *http.Request) ([]Entry, Settings, error) {
	set, err := m.ms.getSettings()
	if err != nil {
		return nil, Settings{}, err
	}
	path, err := resolveLogPath(set, r.URL.Query().Get("log"))
	if err != nil {
		return nil, set, err
	}
	lines, err := m.reader.TailLines(path, set.effectiveMaxLines())
	if err != nil {
		return nil, set, err
	}
	entries := make([]Entry, 0, len(lines))
	for _, line := range lines {
		if e, ok := ParseCombined(line); ok {
			entries = append(entries, e)
		}
	}
	return entries, set, nil
}

func (m *Module) handleOverview(w http.ResponseWriter, r *http.Request) {
	entries, _, err := m.loadEntries(r)
	if err != nil {
		analysisError(w, err)
		return
	}
	rng := timeRange(r)
	agg := NewAggregator(rng)
	for _, e := range entries {
		agg.Add(e)
	}
	writeJSON(w, http.StatusOK, agg.Report(topN(r)))
}

func (m *Module) handleSites(w http.ResponseWriter, r *http.Request) {
	entries, _, err := m.loadEntries(r)
	if err != nil {
		analysisError(w, err)
		return
	}
	agg := NewAggregator(timeRange(r))
	for _, e := range entries {
		agg.Add(e)
	}
	writeJSON(w, http.StatusOK, agg.Sites())
}

func (m *Module) handleTrend(w http.ResponseWriter, r *http.Request) {
	entries, _, err := m.loadEntries(r)
	if err != nil {
		analysisError(w, err)
		return
	}
	gran := r.URL.Query().Get("granularity")
	if gran != "day" {
		gran = "hour"
	}
	writeJSON(w, http.StatusOK, Trend(entries, timeRange(r), gran))
}

func (m *Module) handleTop(w http.ResponseWriter, r *http.Request) {
	entries, _, err := m.loadEntries(r)
	if err != nil {
		analysisError(w, err)
		return
	}
	agg := NewAggregator(timeRange(r))
	for _, e := range entries {
		agg.Add(e)
	}
	rep := agg.Report(topN(r))
	var out []Count
	switch r.URL.Query().Get("kind") {
	case "ip":
		out = rep.TopIPs
	case "ua":
		out = rep.TopUAs
	default:
		out = rep.TopURLs
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	entries, _, err := m.loadEntries(r)
	if err != nil {
		analysisError(w, err)
		return
	}
	agg := NewAggregator(timeRange(r))
	for _, e := range entries {
		agg.Add(e)
	}
	rep := agg.Report(topN(r))
	if err := m.ms.saveSnapshot("-", rep); err != nil {
		serverError(w, "save snapshot", err)
		return
	}
	m.deps.Audit(&uid, "sitemonitor.snapshot", strconv.FormatInt(rep.TotalRequests, 10)+" reqs", m.clientIP(r))
	writeJSON(w, http.StatusOK, rep)
}

// --- query params ---

// timeRange 解析 from/to 查询参数(RFC3339 或 Unix 秒);非法/缺失则该端不限。
func timeRange(r *http.Request) TimeRange {
	return TimeRange{
		From: parseTime(r.URL.Query().Get("from")),
		To:   parseTime(r.URL.Query().Get("to")),
	}
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0)
	}
	return time.Time{}
}

// topN 解析 top 查询参数(1..1000),默认 10。
func topN(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("top"))
	if err != nil || n <= 0 {
		return 10
	}
	if n > 1000 {
		return 1000
	}
	return n
}

// --- helpers ---

func analysisError(w http.ResponseWriter, err error) {
	log.Printf("sitemonitor: analysis failed: %v", err)
	http.Error(w, "log analysis unavailable", http.StatusInternalServerError)
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(v); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return false
	}
	return true
}

func serverError(w http.ResponseWriter, what string, err error) {
	log.Printf("sitemonitor: %s failed: %v", what, err)
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
