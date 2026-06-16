// Package sites 实现 nginx 网站管理模块(对标 aaPanel 建站):
// 列出/创建(静态、反代、PHP)/删除/启停 vhost,并管理域名、PHP 版本、伪静态、
// SSL、目录保护、重定向、防盗链、默认文档、运行目录、原始配置与日志。
// 任何设置变更都重生成完整 server block,写盘后经 nginx -t 校验通过才 reload,失败回滚不 reload。
//
// 安全要点:
//   - 域名/路径/upstream/端口/socket/扩展名/referer/用户名/重定向/php版本 全部白名单校验,
//     非法即拒,绝不拼进配置(防换行注入);generateConfig 渲染后 assertConfigNoInjection 兜底。
//   - 配置由 generate.go 组合;写盘后 nginx -t 通过才 reload,失败回滚旧配置。
//   - 变更需 operator+;删除/禁用为危险操作,需 admin + X-Confirm-Danger + 审计。
//   - 目录保护口令以 apr1 哈希落 .htpasswd,绝不明文。
//   - 可配置路径持久化在 site_settings 表,仅 admin 可改。
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
	ClientIP  func(*http.Request) string
}

// Module 是可开关的网站管理模块。nginx 副作用经 Nginx 接口抽象(可注入 mock)。
type Module struct {
	ss        *siteStore
	deps      Deps
	hasher    PassHasher
	newNginx  func(confDir string) Nginx
	newIssuer func() acmeIssuer
	available func() error
	archiver  Archiver
	stopCh    chan struct{}
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
		hasher:    newAPR1Hasher(nil),
		newNginx:  func(confDir string) Nginx { return newRealNginx(confDir) },
		newIssuer: func() acmeIssuer { return newRealACME() },
		available: func() error { return newRealNginx("").Available() },
		archiver:  &realArchiver{},
	}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "sites", Name: "网站", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "网站", Icon: "globe", Path: "/sites"}}
}

// Start 起每日续期巡检 goroutine。Manager 持锁调用,必须立即返回:仅起 detached 循环。
func (m *Module) Start(context.Context) error {
	m.stopCh = make(chan struct{})
	go m.renewLoop(m.stopCh)
	return nil
}

// Stop 关停续期巡检。
func (m *Module) Stop(context.Context) error {
	if m.stopCh != nil {
		close(m.stopCh)
		m.stopCh = nil
	}
	return nil
}

// HealthCheck:nginx 不在 PATH 则不允许启用。
func (m *Module) HealthCheck() error { return m.available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/sites", m.handleList)
	r.Post("/sites", m.handleCreate)
	r.Get("/sites/{id}", m.handleGet)
	r.Delete("/sites/{id}", m.handleDelete)
	r.Post("/sites/{id}/{verb:enable|disable}", m.handleToggle)

	r.Put("/sites/{id}/domains", m.handlePutDomains)
	r.Get("/sites/{id}/php", m.handleGetPHP)
	r.Put("/sites/{id}/php", m.handlePutPHP)

	r.Get("/rewrite-templates", m.handleRewriteTemplates)
	r.Get("/sites/{id}/rewrite", m.handleGetRewrite)
	r.Put("/sites/{id}/rewrite", m.handlePutRewrite)

	r.Get("/sites/{id}/proxy", m.handleGetProxy)
	r.Put("/sites/{id}/proxy", m.handlePutProxy)

	r.Put("/sites/{id}/limits", m.handlePutLimits)

	r.Get("/sites/{id}/default-docs", m.handleGetDefaultDocs)
	r.Put("/sites/{id}/default-docs", m.handlePutDefaultDocs)

	r.Get("/sites/{id}/dir-protect", m.handleGetDirProtect)
	r.Post("/sites/{id}/dir-protect", m.handleAddDirProtect)
	r.Delete("/sites/{id}/dir-protect", m.handleDeleteDirProtect)

	r.Get("/sites/{id}/redirects", m.handleGetRedirects)
	r.Put("/sites/{id}/redirects", m.handlePutRedirects)

	r.Get("/sites/{id}/anti-leech", m.handleGetAntiLeech)
	r.Put("/sites/{id}/anti-leech", m.handlePutAntiLeech)

	r.Get("/sites/{id}/ssl", m.handleGetSSL)
	r.Put("/sites/{id}/ssl", m.handlePutSSL)
	r.Post("/sites/{id}/ssl/acme", m.handleACMEIssue)

	r.Get("/sites/{id}/logs", m.handleLogs)
	r.Put("/sites/{id}/logs", m.handlePutLogConfig)
	r.Get("/sites/{id}/logs/{kind:access|error}/download", m.handleLogDownload)
	r.Get("/sites/{id}/run-dir", m.handleGetRunDir)
	r.Put("/sites/{id}/run-dir", m.handlePutRunDir)
	r.Put("/sites/{id}/root", m.handlePutRoot)
	r.Put("/sites/{id}/error-pages", m.handlePutErrorPages)

	r.Get("/sites/{id}/config", m.handleGetConfig)
	r.Put("/sites/{id}/config", m.handleEditConfig) // 危险写:原始配置可绕白名单,需 admin + 二次确认

	r.Post("/sites/{id}/backups", m.handleCreateBackup)
	r.Get("/sites/{id}/backups", m.handleListBackups)
	r.Get("/sites/{id}/backups/{bid}/download", m.handleDownloadBackup)

	r.Get("/settings", m.handleGetSettings)
	r.Put("/settings", m.handlePutSettings)
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
	site, ok := m.loadSite(w, r)
	if !ok {
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	st, err := buildSite(req, set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.ss.getByName(st.Name); err == nil {
		http.Error(w, "site with this name already exists", http.StatusConflict)
		return
	}
	cfg, err := siteToConfig(st, set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	config, err := generateConfig(cfg)
	if err != nil {
		log.Printf("sites: render failed: %v", err)
		http.Error(w, "config generation failed", http.StatusInternalServerError)
		return
	}
	st.Config = config

	ng := m.newNginx(set.ConfDir)
	if err := m.writeAndReload(ng, st.Name, config); err != nil {
		log.Printf("sites: create %q apply failed: %v", st.Name, err)
		http.Error(w, "nginx validation failed; site not created", http.StatusBadRequest)
		return
	}
	st.CreatedBy = &uid
	id, err := m.ss.create(st)
	if err != nil {
		log.Printf("sites: persist failed: %v", err)
		_ = ng.RemoveConfig(st.Name)
		_ = ng.Reload()
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.create", st.Name+" ("+st.Kind+")", m.clientIP(r))
	created, _ := m.ss.get(id)
	writeJSON(w, http.StatusCreated, created)
}

// applySite 重生成配置 → 写 .htpasswd → 写 conf → nginx -t → reload,
// 成功则持久化更新。失败时回滚到旧配置并 reload,DB 不变。
func (m *Module) applySite(w http.ResponseWriter, r *http.Request, st Site, action, detail string) bool {
	set, ok := m.loadSettings(w)
	if !ok {
		return false
	}
	cfg, err := siteToConfig(st, set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return false
	}
	config, err := generateConfig(cfg)
	if err != nil {
		http.Error(w, "config generation failed: "+err.Error(), http.StatusBadRequest)
		return false
	}
	st.Config = config

	ng := m.newNginx(set.ConfDir)
	if len(st.DirProtect) > 0 {
		if err := ng.WriteHtpasswd(st.Name, htpasswdFile(st.DirProtect)); err != nil {
			http.Error(w, "htpasswd write failed", http.StatusInternalServerError)
			return false
		}
	} else {
		_ = ng.RemoveHtpasswd(st.Name)
	}
	if st.Enabled {
		if err := m.writeAndReload(ng, st.Name, config); err != nil {
			// 回滚:恢复 DB 中旧配置并 reload,使 nginx 与持久态一致。
			if old, e := m.ss.get(st.ID); e == nil {
				_ = ng.WriteConfig(old.Name, old.Config)
				_ = ng.Reload()
			}
			log.Printf("sites: %s %q rejected: %v", action, st.Name, err)
			http.Error(w, "nginx validation failed; change not applied", http.StatusBadRequest)
			return false
		}
	}
	if err := m.ss.update(st); err != nil {
		log.Printf("sites: persist %s failed: %v", action, err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return false
	}
	uid, _ := m.deps.Principal(r)
	m.deps.Audit(&uid, action, detail, m.clientIP(r))
	updated, _ := m.ss.get(st.ID)
	writeJSON(w, http.StatusOK, updated)
	return true
}

func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	enable := verb == "enable"
	uid, ok := m.requireToggle(w, r, enable)
	if !ok {
		return
	}
	site, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return
	}
	set, ok := m.loadSettings(w)
	if !ok {
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
	uid, ok := m.requireDanger(w, r)
	if !ok {
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
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	ng := m.newNginx(set.ConfDir)
	if err := ng.RemoveConfig(site.Name); err != nil {
		log.Printf("sites: remove config %q failed: %v", site.Name, err)
		http.Error(w, "nginx operation failed", http.StatusInternalServerError)
		return
	}
	_ = ng.RemoveHtpasswd(site.Name)
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

// handleEditConfig 替换原始配置:写盘 → nginx -t → reload。失败回滚。需 admin + 二次确认。
func (m *Module) handleEditConfig(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireDanger(w, r)
	if !ok {
		return
	}
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	var req struct {
		Config string `json:"config"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := validNginxFragment(req.Config); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	set, ok := m.loadSettings(w)
	if !ok {
		return
	}
	ng := m.newNginx(set.ConfDir)
	if err := m.writeAndReload(ng, site.Name, req.Config); err != nil {
		_ = ng.WriteConfig(site.Name, site.Config)
		_ = ng.Reload()
		log.Printf("sites: edit %q rejected: %v", site.Name, err)
		http.Error(w, "nginx validation failed; config unchanged", http.StatusBadRequest)
		return
	}
	if err := m.ss.updateConfig(site.ID, req.Config); err != nil {
		log.Printf("sites: persist config failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "sites.config.edit", site.Name, m.clientIP(r))
	updated, _ := m.ss.get(site.ID)
	writeJSON(w, http.StatusOK, updated)
}

func (m *Module) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	site, ok := m.loadSite(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"config": site.Config})
}

// --- settings ---

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

// --- shared helpers ---

// writeAndReload 写配置 → nginx -t → reload。Test 失败绝不 reload,并移除刚写的坏配置。
func (m *Module) writeAndReload(ng Nginx, name, config string) error {
	if err := ng.WriteConfig(name, config); err != nil {
		return err
	}
	if err := ng.Test(); err != nil {
		_ = ng.RemoveConfig(name)
		return err
	}
	return ng.Reload()
}

// loadSite 解析 id 并取站点,失败已写响应。
func (m *Module) loadSite(w http.ResponseWriter, r *http.Request) (Site, bool) {
	id, ok := parseID(w, r)
	if !ok {
		return Site{}, false
	}
	site, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "site not found", http.StatusNotFound)
		return Site{}, false
	}
	return site, true
}

func (m *Module) loadSettings(w http.ResponseWriter) (Settings, bool) {
	set, err := m.ss.getSettings()
	if err != nil {
		log.Printf("sites: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return Settings{}, false
	}
	return set, true
}

// requireWriter 校验 operator/admin。失败时已写响应。
func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// requireDanger 校验危险操作:X-Confirm-Danger + admin。
func (m *Module) requireDanger(w http.ResponseWriter, r *http.Request) (int64, bool) {
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

// requireToggle:enable 走 operator+;disable 为危险操作,需 admin + 二次确认。
func (m *Module) requireToggle(w http.ResponseWriter, r *http.Request, enable bool) (int64, bool) {
	if enable {
		return m.requireWriter(w, r)
	}
	return m.requireDanger(w, r)
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
