// Package nodejs 实现 Node 项目管理模块(对标 aaPanel Node 项目):
// 列出/创建/删除/启停重启项目、查看状态与日志,检测已装 Node 版本。
// 项目元数据存自建表,真实进程经 ProcessManager 抽象(默认 supervisor 后端)。
//
// 安全要点:
//   - 项目名/目录/启动命令/端口/Node 版本全部白名单校验,非法即拒,绝不拼进配置或 exec 参数。
//   - 项目目录限定在可配置基目录内,拒绝路径穿越。
//   - 创建项目可指定任意启动命令(以 supervisor 属主执行),需 admin;start/stop/restart 等不定义新命令的操作 operator+。
//   - 删除/停止为危险操作,需 admin + X-Confirm-Danger + 审计。
//   - 可配置路径(项目根基目录/Node 安装目录/进程配置目录/日志目录)持久化在 nodejs_settings 表,仅 admin 可改。
package nodejs

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
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Settings 是可配置的路径与默认值,持久化在 nodejs_settings 表。
type Settings struct {
	BaseDir string `json:"base_dir"` // 项目根基目录,项目目录限定其下
	NodeDir string `json:"node_dir"` // Node 安装目录(bin 所在),前置到进程 PATH
	ConfDir string `json:"conf_dir"` // 进程管理器(supervisor)配置目录
	LogDir  string `json:"log_dir"`  // 项目 stdout/stderr 日志目录
}

// DefaultSettings 返回内置默认值(对标 aaPanel 习惯)。
func DefaultSettings() Settings {
	return Settings{
		BaseDir: "/www/nodejs",
		NodeDir: "/usr/local/bin",
		ConfDir: "/etc/supervisor/conf.d",
		LogDir:  "/www/wwwlogs/nodejs",
	}
}

func (s Settings) validate() error {
	if err := validAbsDir(s.BaseDir); err != nil {
		return err
	}
	if err := validAbsDir(s.NodeDir); err != nil {
		return err
	}
	if err := validAbsDir(s.ConfDir); err != nil {
		return err
	}
	return validAbsDir(s.LogDir)
}

// Module 是可开关的 Node 项目管理模块。进程副作用经 ProcessManager 抽象(可注入 mock)。
type Module struct {
	ns   *nodeStore
	pm   ProcessManager
	deps Deps
}

// New 建表并返回模块。建表失败直接 panic:模块无法工作。
func New(st *store.Store, pm ProcessManager, deps Deps) *Module {
	ns, err := newNodeStore(st)
	if err != nil {
		panic("nodejs: init store: " + err.Error())
	}
	return &Module{ns: ns, pm: pm, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "nodejs", Name: "Node 项目", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "Node 项目", Icon: "hexagon", Path: "/nodejs"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:node 与进程管理器须可用,否则不允许启用。
func (m *Module) HealthCheck() error { return m.pm.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/projects", m.handleList)                                   // 只读
	r.Post("/projects", m.handleCreate)                                // 写:admin(可指定任意启动命令 → 提权风险)
	r.Delete("/projects/{id}", m.handleDelete)                         // 危险写:admin + 确认
	r.Get("/projects/{id}/status", m.handleStatus)                     // 只读
	r.Get("/projects/{id}/logs", m.handleLogs)                         // 只读
	r.Post("/projects/{id}/{verb:start|stop|restart}", m.handleAction) // 写:operator+(stop 危险)
	r.Get("/versions", m.handleVersions)                               // 只读:已装 Node 版本
	r.Get("/settings", m.handleGetSettings)                            // 只读
	r.Put("/settings", m.handlePutSettings)                            // 写:admin
}

type projectRequest struct {
	Name        string `json:"name"`
	Directory   string `json:"directory"` // 相对基目录或基目录内绝对路径
	Command     string `json:"command"`
	Port        int    `json:"port"`
	NodeVersion string `json:"node_version"`
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	ps, err := m.ns.list()
	if err != nil {
		log.Printf("nodejs: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if ps == nil {
		ps = []Project{}
	}
	writeJSON(w, http.StatusOK, ps)
}

// handleCreate 创建项目:可指定任意启动命令,该命令以 supervisor 属主(通常 root)执行,
// 故须 admin —— operator 不得借此定义任意命令获得提权。start/stop/restart 等不定义新命令的操作仍是 operator+。
func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req projectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	set, err := m.ns.loadSettings()
	if err != nil {
		log.Printf("nodejs: load settings failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	// 严格校验:任一非法即 400,绝不进模板/exec(无审计、无 reload)。
	if !ValidProjectName(req.Name) {
		http.Error(w, "invalid project name (alnum start, alnum . _ - only, max 64)", http.StatusBadRequest)
		return
	}
	if !ValidStartCommand(req.Command) {
		http.Error(w, "invalid command (non-empty, single line, no control chars)", http.StatusBadRequest)
		return
	}
	if !ValidPort(req.Port) {
		http.Error(w, "invalid port (1..65535)", http.StatusBadRequest)
		return
	}
	if !ValidNodeVersion(req.NodeVersion) {
		http.Error(w, "invalid node version", http.StatusBadRequest)
		return
	}
	dir, err := safeProjectDir(set.BaseDir, req.Directory)
	if err != nil {
		// 错误详情含 base 路径,仅记日志;响应给通用文案,避免泄露服务端目录布局。
		log.Printf("nodejs: invalid project directory: %v", err)
		http.Error(w, "invalid directory", http.StatusBadRequest)
		return
	}

	id, err := m.ns.create(Project{
		Name: req.Name, Directory: dir, Command: req.Command,
		Port: req.Port, NodeVersion: req.NodeVersion, CreatedBy: &uid,
	})
	if err != nil {
		http.Error(w, "create failed (duplicate name?)", http.StatusConflict)
		return
	}
	spec := ProcessSpec{
		Name: req.Name, Directory: dir, Command: req.Command, Port: req.Port,
		NodePath: set.NodeDir, LogDir: set.LogDir,
	}
	if err := m.pm.Apply(set.ConfDir, spec); err != nil {
		_ = m.ns.delete(id) // 回滚元数据:配置没落盘,不留孤儿记录。
		log.Printf("nodejs: apply config failed: %v", err)
		http.Error(w, "apply process config failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "nodejs.create", req.Name, m.clientIP(r))
	p, _ := m.ns.get(id)
	writeJSON(w, http.StatusCreated, p)
}

// handleDelete 删除项目:停进程、删配置与元数据。危险操作,需 admin + 二次确认。
func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	p, err := m.ns.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	set, err := m.ns.loadSettings()
	if err != nil {
		log.Printf("nodejs: load settings failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	// 先停再删配置,避免删了配置仍有进程残留。stop 失败不阻断删除(可能本就没起)。
	_, _ = m.pm.Action("stop", p.Name)
	if err := m.pm.Remove(set.ConfDir, p.Name); err != nil {
		log.Printf("nodejs: remove config failed: %v", err)
		http.Error(w, "remove config failed", http.StatusInternalServerError)
		return
	}
	if err := m.ns.delete(id); err != nil {
		log.Printf("nodejs: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "nodejs.delete", p.Name, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	p, err := m.ns.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	out, err := m.pm.Status(p.Name)
	if err != nil {
		log.Printf("nodejs: status failed: %v", err)
		http.Error(w, "status unavailable", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleLogs(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	p, err := m.ns.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	lines := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lines = n
		}
	}
	stderr := r.URL.Query().Get("stream") == "stderr"
	out, err := m.pm.TailLog(p.Name, lines, stderr)
	if err != nil {
		log.Printf("nodejs: tail log failed: %v", err)
		http.Error(w, "log unavailable", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleAction(w http.ResponseWriter, r *http.Request) {
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	// stop 会终止运行中的项目,属危险操作:需二次确认。
	if verb == "stop" && !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	p, err := m.ns.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	out, err := m.pm.Action(verb, p.Name)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "nodejs."+verb, p.Name+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("nodejs: %s %q failed: %v", verb, p.Name, err)
		http.Error(w, "process operation failed", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleVersions(w http.ResponseWriter, _ *http.Request) {
	vs := m.pm.NodeVersions()
	if vs == nil {
		vs = []string{}
	}
	writeJSON(w, http.StatusOK, vs)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ns.loadSettings()
	if err != nil {
		log.Printf("nodejs: load settings failed: %v", err)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&set); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := set.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.ns.saveSettings(set); err != nil {
		log.Printf("nodejs: save settings failed: %v", err)
		http.Error(w, "save settings failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "nodejs.settings", set.BaseDir+" "+set.NodeDir, m.clientIP(r))
	writeJSON(w, http.StatusOK, set)
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

// requireAdmin 校验 admin。失败时已写响应,返回 ok=false。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
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

func writePlain(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(s))
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
