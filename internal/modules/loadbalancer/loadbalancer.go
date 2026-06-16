// Package loadbalancer 实现 nginx 负载均衡模块(对标 aaPanel 负载均衡):
// 列出/创建/删除/启停均衡组(nginx upstream + 配套 server proxy_pass),
// 生成的配置经 nginx -t 校验后才 reload。
//
// 安全要点:
//   - upstream 名/后端地址(host:port)/权重/算法/健康检查参数全部白名单校验,
//     非法即拒,绝不拼进配置(防换行注入)。
//   - 配置由 text/template 生成;写盘后 nginx -t 通过才 reload,失败不 reload。
//   - 创建需 operator+;删除/禁用为危险操作,需 admin + X-Confirm-Danger + 审计。
//   - 可配置 upstream 配置目录持久化在 lb_settings 表,仅 admin 可改。
package loadbalancer

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

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
	ClientIP  func(*http.Request) string // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的负载均衡模块。nginx 副作用经 Nginx 接口抽象(可注入 mock)。
type Module struct {
	ls        *lbStore
	deps      Deps
	newNginx  func(confDir string) Nginx // 工厂:按当前设置的 confDir 构造控制器,便于测试替换
	available func() error               // HealthCheck 用:nginx 是否在 PATH
}

// New 建表并返回模块。建表失败直接 panic(模块无法工作)。
func New(st *store.Store, deps Deps) *Module {
	ls, err := newLBStore(st)
	if err != nil {
		panic("loadbalancer: init store: " + err.Error())
	}
	return &Module{
		ls:        ls,
		deps:      deps,
		newNginx:  func(confDir string) Nginx { return newRealNginx(confDir) },
		available: func() error { return newRealNginx("").Available() },
	}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "loadbalancer", Name: "负载均衡", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "负载均衡", Icon: "git-fork", Path: "/loadbalancer"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:nginx 不在 PATH 则不允许启用。
func (m *Module) HealthCheck() error { return m.available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/groups", m.handleList)                               // 只读
	r.Post("/groups", m.handleCreate)                            // 写:operator+
	r.Get("/groups/{id}", m.handleGet)                           // 只读:含生成的配置
	r.Post("/groups/{id}/{verb:enable|disable}", m.handleToggle) // 写;disable 危险
	r.Delete("/groups/{id}", m.handleDelete)                     // 危险写:admin + 二次确认
	r.Get("/settings", m.handleGetSettings)                      // 只读
	r.Put("/settings", m.handlePutSettings)                      // 写:admin
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	groups, err := m.ls.list()
	if err != nil {
		log.Printf("loadbalancer: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if groups == nil {
		groups = []LBGroup{}
	}
	writeJSON(w, http.StatusOK, groups)
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	g, err := m.ls.get(id)
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// 严格校验:非法即 400,绝不进模板/exec(无审计、无 reload)。
	g, err := buildGroup(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.ls.getByName(g.Name); err == nil {
		http.Error(w, "group with this name already exists", http.StatusConflict)
		return
	}
	config, err := renderGroup(g)
	if err != nil {
		log.Printf("loadbalancer: render failed: %v", err)
		http.Error(w, "config generation failed", http.StatusInternalServerError)
		return
	}

	set, err := m.ls.getSettings()
	if err != nil {
		log.Printf("loadbalancer: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	ng := m.newNginx(set.ConfDir)
	if err := m.writeAndReload(ng, g.Name, config); err != nil {
		log.Printf("loadbalancer: create %q apply failed: %v", g.Name, err)
		http.Error(w, "nginx validation failed; group not created", http.StatusBadRequest)
		return
	}

	id, err := m.ls.create(LBGroup{
		Name: g.Name, Algo: g.Algo, Listen: g.Listen, ServerName: g.ServerName,
		Backends: g.Backends, Enabled: true, Config: config, CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("loadbalancer: persist failed: %v", err)
		_ = ng.RemoveConfig(g.Name)
		_ = ng.Reload()
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "loadbalancer.create", g.Name+" ("+g.Algo+")", m.clientIP(r))
	created, _ := m.ls.get(id)
	writeJSON(w, http.StatusCreated, created)
}

func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	enable := verb == "enable"
	// disable 会下线均衡组,属危险操作:需 admin + 二次确认。
	uid, ok := m.requireToggle(w, r, enable)
	if !ok {
		return
	}
	g, err := m.ls.get(id)
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	set, err := m.ls.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	ng := m.newNginx(set.ConfDir)
	var applyErr error
	if enable {
		applyErr = m.writeAndReload(ng, g.Name, g.Config)
	} else {
		if applyErr = ng.RemoveConfig(g.Name); applyErr == nil {
			applyErr = ng.Reload()
		}
	}
	if applyErr != nil {
		log.Printf("loadbalancer: %s %q failed: %v", verb, g.Name, applyErr)
		http.Error(w, "nginx operation failed", http.StatusBadRequest)
		return
	}
	if err := m.ls.setEnabled(id, enable); err != nil {
		log.Printf("loadbalancer: persist toggle failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "loadbalancer."+verb, g.Name, m.clientIP(r))
	updated, _ := m.ls.get(id)
	writeJSON(w, http.StatusOK, updated)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	g, err := m.ls.get(id)
	if err != nil {
		http.Error(w, "group not found", http.StatusNotFound)
		return
	}
	set, err := m.ls.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	ng := m.newNginx(set.ConfDir)
	if err := ng.RemoveConfig(g.Name); err != nil {
		log.Printf("loadbalancer: remove config %q failed: %v", g.Name, err)
		http.Error(w, "nginx operation failed", http.StatusInternalServerError)
		return
	}
	// 删除配置后 reload;reload 失败不阻断 DB 删除(配置已不在,组逻辑上已删)。
	if err := ng.Reload(); err != nil {
		log.Printf("loadbalancer: reload after delete %q failed: %v", g.Name, err)
	}
	if err := m.ls.delete(id); err != nil {
		log.Printf("loadbalancer: delete persist failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "loadbalancer.delete", g.Name, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ls.getSettings()
	if err != nil {
		log.Printf("loadbalancer: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, set)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var set Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&set); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := set.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ls.putSettings(set); err != nil {
		log.Printf("loadbalancer: persist settings failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "loadbalancer.settings.update", set.ConfDir, m.clientIP(r))
	writeJSON(w, http.StatusOK, set)
}

// writeAndReload 写配置 → nginx -t → reload。Test 失败绝不 reload,并移除刚写的坏配置。
func (m *Module) writeAndReload(ng Nginx, name, config string) error {
	if err := ng.WriteConfig(name, config); err != nil {
		return err
	}
	if err := ng.Test(); err != nil {
		_ = ng.RemoveConfig(name) // 坏配置不留在 confDir,避免污染后续 nginx -t
		return err
	}
	return ng.Reload()
}

// requireWriter 校验 operator/admin。失败时已写响应,返回 ok=false。
func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// requireToggle:enable 走 operator+;disable 为危险操作,需 admin + 二次确认。
func (m *Module) requireToggle(w http.ResponseWriter, r *http.Request, enable bool) (int64, bool) {
	if enable {
		return m.requireWriter(w, r)
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return 0, false
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

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
