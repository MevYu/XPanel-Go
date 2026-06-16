// Package sites 实现 nginx 网站管理模块(对标 aaPanel 建站):
// 列出/创建(静态、反代、PHP)/删除/启停 vhost,生成的配置经 nginx -t 校验后才 reload。
//
// 安全要点:
//   - 域名/路径/upstream/端口/socket 全部白名单校验,非法即拒,绝不拼进配置(防换行注入)。
//   - 配置由 text/template 生成;写盘后 nginx -t 通过才 reload,失败不 reload。
//   - 变更需 operator+;删除/禁用为危险操作,需 admin + X-Confirm-Danger + 审计。
//   - 可配置路径(web 根/conf 目录/日志目录/php socket)持久化在 site_settings 表,仅 admin 可改。
package sites

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

// Module 是可开关的网站管理模块。nginx 副作用经 Nginx 接口抽象(可注入 mock)。
type Module struct {
	ss        *siteStore
	deps      Deps
	newNginx  func(confDir string) Nginx // 工厂:按当前设置的 confDir 构造控制器,便于测试替换
	available func() error               // HealthCheck 用:nginx 是否在 PATH
}

// New 建表并返回模块。建表失败直接 panic(模块无法工作)。
func New(st *store.Store, deps Deps) *Module {
	ss, err := newSiteStore(st)
	if err != nil {
		panic("sites: init store: " + err.Error())
	}
	return &Module{
		ss:        ss,
		deps:      deps,
		newNginx:  func(confDir string) Nginx { return newRealNginx(confDir) },
		available: func() error { return newRealNginx("").Available() },
	}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "sites", Name: "网站", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "网站", Icon: "globe", Path: "/sites"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:nginx 不在 PATH 则不允许启用。
func (m *Module) HealthCheck() error { return m.available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/sites", m.handleList)                               // 只读
	r.Post("/sites", m.handleCreate)                            // 写:operator+
	r.Get("/sites/{id}", m.handleGet)                           // 只读:含生成的配置
	r.Put("/sites/{id}/config", m.handleEditConfig)             // 危险写:原始配置可绕白名单,需 admin + 二次确认
	r.Post("/sites/{id}/{verb:enable|disable}", m.handleToggle) // 写;disable 危险
	r.Delete("/sites/{id}", m.handleDelete)                     // 危险写:admin + 二次确认
	r.Get("/settings", m.handleGetSettings)                     // 只读
	r.Put("/settings", m.handlePutSettings)                     // 写:admin
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	sites, err := m.ss.list()
	if err != nil {
		log.Printf("sites: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if sites == nil {
		sites = []Site{}
	}
	writeJSON(w, http.StatusOK, sites)
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	site, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, site)
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req createRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	set, err := m.ss.getSettings()
	if err != nil {
		log.Printf("sites: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	// 严格校验:非法即 400,绝不进模板/exec(无审计、无 reload)。
	v, err := buildVHost(req, set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.ss.getByName(v.Name); err == nil {
		http.Error(w, "site with this name already exists", http.StatusConflict)
		return
	}
	config, err := renderVHost(v)
	if err != nil {
		log.Printf("sites: render failed: %v", err)
		http.Error(w, "config generation failed", http.StatusInternalServerError)
		return
	}

	ng := m.newNginx(set.ConfDir)
	if err := m.writeAndReload(ng, v.Name, config); err != nil {
		log.Printf("sites: create %q apply failed: %v", v.Name, err)
		http.Error(w, "nginx validation failed; site not created", http.StatusBadRequest)
		return
	}

	id, err := m.ss.create(Site{
		Name: v.Name, Domains: v.Domains, Kind: string(v.Kind), Listen: v.Listen,
		Enabled: true, Config: config, CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("sites: persist failed: %v", err)
		_ = ng.RemoveConfig(v.Name)
		_ = ng.Reload()
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.create", v.Name+" ("+string(v.Kind)+")", m.clientIP(r))
	site, _ := m.ss.get(id)
	writeJSON(w, http.StatusCreated, site)
}

// handleEditConfig 替换站点配置:写盘 → nginx -t → reload。校验失败回滚旧配置。
// 写入的是原始 nginx 配置,可绕过建站白名单(如 location 读任意文件),
// 故与 delete/disable 同危险级:需 admin + 二次确认。
func (m *Module) handleEditConfig(w http.ResponseWriter, r *http.Request) {
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
	site, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	set, err := m.ss.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	ng := m.newNginx(set.ConfDir)
	// 先写新配置并测试;失败则恢复旧配置并 reload,保证 nginx 始终处于一致状态。
	if err := m.writeAndReload(ng, site.Name, req.Config); err != nil {
		_ = ng.WriteConfig(site.Name, site.Config)
		_ = ng.Reload()
		log.Printf("sites: edit %q rejected: %v", site.Name, err)
		http.Error(w, "nginx validation failed; config unchanged", http.StatusBadRequest)
		return
	}
	if err := m.ss.updateConfig(id, req.Config); err != nil {
		log.Printf("sites: persist config failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.config.edit", site.Name, m.clientIP(r))
	updated, _ := m.ss.get(id)
	writeJSON(w, http.StatusOK, updated)
}

func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	enable := verb == "enable"
	// disable 会下线站点,属危险操作:需 admin + 二次确认。
	uid, ok := m.requireToggle(w, r, enable)
	if !ok {
		return
	}
	site, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	set, err := m.ss.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	ng := m.newNginx(set.ConfDir)
	var applyErr error
	if enable {
		applyErr = m.writeAndReload(ng, site.Name, site.Config)
	} else {
		if applyErr = ng.RemoveConfig(site.Name); applyErr == nil {
			applyErr = ng.Reload()
		}
	}
	if applyErr != nil {
		log.Printf("sites: %s %q failed: %v", verb, site.Name, applyErr)
		http.Error(w, "nginx operation failed", http.StatusBadRequest)
		return
	}
	if err := m.ss.setEnabled(id, enable); err != nil {
		log.Printf("sites: persist toggle failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites."+verb, site.Name, m.clientIP(r))
	updated, _ := m.ss.get(id)
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
	site, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	set, err := m.ss.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	ng := m.newNginx(set.ConfDir)
	if err := ng.RemoveConfig(site.Name); err != nil {
		log.Printf("sites: remove config %q failed: %v", site.Name, err)
		http.Error(w, "nginx operation failed", http.StatusInternalServerError)
		return
	}
	// 删除配置后 reload;reload 失败不阻断 DB 删除(配置已不在,站点逻辑上已删)。
	if err := ng.Reload(); err != nil {
		log.Printf("sites: reload after delete %q failed: %v", site.Name, err)
	}
	if err := m.ss.delete(id); err != nil {
		log.Printf("sites: delete persist failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.delete", site.Name, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ss.getSettings()
	if err != nil {
		log.Printf("sites: settings load failed: %v", err)
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
	if err := m.ss.putSettings(set); err != nil {
		log.Printf("sites: persist settings failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.settings.update", set.WebRoot+" "+set.ConfDir, m.clientIP(r))
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
