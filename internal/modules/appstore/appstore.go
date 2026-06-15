// Package appstore 实现应用商店/一键部署模块(对标 1Panel/aaPanel 应用商店):
// 内置一组 compose 模板应用,用户填参数后渲染 compose 并 `docker compose up -d`,
// 记录已安装实例,支持启停/卸载/状态/日志。
//
// 安全要点:
//   - 应用 id、实例名、参数全部白名单校验,非法即 400,绝不进模板/exec(防 YAML/命令注入)。
//   - 参数进 compose 经 yq 单引号转义(text/template 函数),作为校验之外的第二道防线。
//   - docker compose 经 exec.Command 参数数组调用,绝不拼 shell。
//   - compose 副作用经 Compose 接口抽象,可注入 mock 单测。
//   - 安装/卸载需 admin;卸载为危险操作,需 X-Confirm-Danger + 审计。
//   - 可配置路径(应用数据根/compose 项目目录)持久化在 appstore_settings 表,仅 admin 可改。
package appstore

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string)
	Audit     func(userID *int64, action, detail, ip string)
}

// Module 是可开关的应用商店模块。compose 副作用经 Compose 接口抽象(可注入 mock)。
type Module struct {
	as      *appStore
	deps    Deps
	compose Compose
}

// New 建表并返回模块。建表失败直接 panic(模块无法工作)。
func New(st *store.Store, deps Deps) *Module {
	as, err := newAppStore(st)
	if err != nil {
		panic("appstore: init store: " + err.Error())
	}
	return &Module{as: as, deps: deps, compose: newRealCompose()}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "appstore", Name: "应用商店", Category: "应用"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "应用商店", Icon: "layout-grid", Path: "/appstore"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:docker 与 docker compose 不可用则不允许启用。
func (m *Module) HealthCheck() error { return m.compose.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/apps", m.handleCatalog)                             // 只读:内置应用目录
	r.Get("/instances", m.handleList)                           // 只读:已安装实例
	r.Get("/instances/{id}", m.handleGet)                       // 只读
	r.Get("/instances/{id}/status", m.handleStatus)             // 只读:compose ps
	r.Get("/instances/{id}/logs", m.handleLogs)                 // 只读:compose logs
	r.Post("/install", m.handleInstall)                         // 写:admin
	r.Post("/instances/{id}/{verb:start|stop}", m.handleToggle) // 写:operator+
	r.Delete("/instances/{id}", m.handleUninstall)              // 危险:admin + 二次确认
	r.Get("/settings", m.handleGetSettings)                     // 只读
	r.Put("/settings", m.handlePutSettings)                     // 写:admin
}

func (m *Module) handleCatalog(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, Catalog())
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	insts, err := m.as.list()
	if err != nil {
		log.Printf("appstore: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if insts == nil {
		insts = []Instance{}
	}
	writeJSON(w, http.StatusOK, insts)
}

func (m *Module) handleGet(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	inst, err := m.as.get(id)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, inst)
}

// installRequest 是安装请求体:应用 id、实例名(可选,缺省由 app id 派生)、参数表。
type installRequest struct {
	AppID  string            `json:"app_id"`
	Name   string            `json:"name"`
	Params map[string]string `json:"params"`
}

func (m *Module) handleInstall(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var req installRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validAppID(req.AppID) {
		http.Error(w, "invalid app id", http.StatusBadRequest)
		return
	}
	app, ok := LookupApp(req.AppID)
	if !ok {
		http.Error(w, "unknown app", http.StatusBadRequest)
		return
	}
	name := req.Name
	if name == "" {
		name = defaultInstanceName(app.ID)
	}
	if !validInstanceName(name) {
		http.Error(w, "invalid instance name", http.StatusBadRequest)
		return
	}
	params, err := validateParams(app, req.Params)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.as.getByName(name); err == nil {
		http.Error(w, "instance with this name already exists", http.StatusConflict)
		return
	}
	set, err := m.as.getSettings()
	if err != nil {
		log.Printf("appstore: settings load failed: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	composeText, err := renderCompose(app, name, params)
	if err != nil {
		log.Printf("appstore: render %q failed: %v", name, err)
		http.Error(w, "compose generation failed", http.StatusInternalServerError)
		return
	}
	projectDir, err := safeProjectDir(set.ProjectDir, name)
	if err != nil {
		http.Error(w, "invalid project directory", http.StatusBadRequest)
		return
	}
	if err := m.compose.WriteProject(projectDir, composeText); err != nil {
		log.Printf("appstore: write project %q failed: %v", name, err)
		http.Error(w, "compose write failed", http.StatusInternalServerError)
		return
	}
	if err := m.compose.Up(name, projectDir); err != nil {
		log.Printf("appstore: compose up %q failed: %v", name, err)
		_ = m.compose.RemoveProjectDir(projectDir)
		http.Error(w, "compose up failed", http.StatusInternalServerError)
		return
	}
	id, err := m.as.create(Instance{
		AppID: app.ID, Name: name, Params: params, Compose: composeText,
		ProjectDir: projectDir, Status: "running", CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("appstore: persist %q failed: %v", name, err)
		_ = m.compose.Down(name, projectDir, false)
		_ = m.compose.RemoveProjectDir(projectDir)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "appstore.install", app.ID+" as "+name, clientIP(r))
	inst, _ := m.as.get(id)
	writeJSON(w, http.StatusCreated, inst)
}

func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	inst, err := m.as.get(id)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	var applyErr error
	newStatus := "running"
	if verb == "stop" {
		applyErr = m.compose.Stop(inst.Name, inst.ProjectDir)
		newStatus = "stopped"
	} else {
		applyErr = m.compose.Start(inst.Name, inst.ProjectDir)
	}
	if applyErr != nil {
		log.Printf("appstore: %s %q failed: %v", verb, inst.Name, applyErr)
		http.Error(w, "compose operation failed", http.StatusInternalServerError)
		return
	}
	if err := m.as.setStatus(id, newStatus); err != nil {
		log.Printf("appstore: persist status %q failed: %v", inst.Name, err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "appstore."+verb, inst.Name, clientIP(r))
	updated, _ := m.as.get(id)
	writeJSON(w, http.StatusOK, updated)
}

func (m *Module) handleUninstall(w http.ResponseWriter, r *http.Request) {
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
	inst, err := m.as.get(id)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}
	// 删数据卷由查询参数显式请求(删数据更危险);默认仅 down 保留卷。
	removeVolumes := r.URL.Query().Get("delete_data") == "true"
	if err := m.compose.Down(inst.Name, inst.ProjectDir, removeVolumes); err != nil {
		log.Printf("appstore: compose down %q failed: %v", inst.Name, err)
		http.Error(w, "compose down failed", http.StatusInternalServerError)
		return
	}
	if err := m.compose.RemoveProjectDir(inst.ProjectDir); err != nil {
		log.Printf("appstore: remove project dir %q failed: %v", inst.Name, err)
	}
	if err := m.as.delete(id); err != nil {
		log.Printf("appstore: delete %q failed: %v", inst.Name, err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	detail := inst.Name
	if removeVolumes {
		detail += " (data deleted)"
	}
	m.deps.Audit(&uid, "appstore.uninstall", detail, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	inst, err := m.as.get(id)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}
	out, err := m.compose.PS(inst.Name, inst.ProjectDir)
	if err != nil {
		log.Printf("appstore: ps %q failed: %v", inst.Name, err)
		http.Error(w, "status unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (m *Module) handleLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	inst, err := m.as.get(id)
	if err != nil {
		http.Error(w, "instance not found", http.StatusNotFound)
		return
	}
	tail := 200
	if t := r.URL.Query().Get("tail"); t != "" {
		if n, err := strconv.Atoi(t); err == nil && n > 0 && n <= 1000 {
			tail = n
		}
	}
	out, err := m.compose.Logs(inst.Name, inst.ProjectDir, tail)
	if err != nil {
		log.Printf("appstore: logs %q failed: %v", inst.Name, err)
		http.Error(w, "logs unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(out))
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.as.getSettings()
	if err != nil {
		log.Printf("appstore: settings load failed: %v", err)
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
	if err := m.as.putSettings(set); err != nil {
		log.Printf("appstore: persist settings failed: %v", err)
		http.Error(w, "persist failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "appstore.settings.update", set.AppsRoot+" "+set.ProjectDir, clientIP(r))
	writeJSON(w, http.StatusOK, set)
}

// defaultInstanceName 由 app id 派生唯一性较高的实例名(时间戳后缀)。
func defaultInstanceName(appID string) string {
	return fmt.Sprintf("%s-%d", appID, time.Now().Unix())
}

// safeProjectDir 把实例名拼到 compose 项目基目录下,拒绝穿越到基目录之外。
func safeProjectDir(base, name string) (string, error) {
	if !validInstanceName(name) {
		return "", fmt.Errorf("invalid instance name %q", name)
	}
	base = filepath.Clean(base)
	joined := filepath.Clean(filepath.Join(base, name))
	if joined != base && !hasPathPrefix(joined, base) {
		return "", fmt.Errorf("resolved project dir escapes base directory")
	}
	return joined, nil
}

func hasPathPrefix(p, base string) bool {
	if p == base {
		return true
	}
	return len(p) > len(base) && p[:len(base)] == base && p[len(base)] == filepath.Separator
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

// clientIP 从 RemoteAddr 取 IP(与 server 层一致,无代理信任)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
