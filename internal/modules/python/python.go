// Package python 实现 Python 项目管理模块(对标 aaPanel Python 项目管理器):
// 项目元数据存自建表,venv 创建/依赖安装经 Provisioner,进程启停查/日志经 Runner,
// 两者均为接口,真实实现走 python -m venv / pip 与 supervisor。
package python

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的 Python 项目管理模块。
type Module struct {
	ps    *pyStore
	prov  Provisioner
	deps  Deps
	mkrun func(set Settings) Runner // 由设置构造 Runner,便于测试注入
}

// New 建表并返回模块。prov 为 venv/依赖安装实现,newRunner 由当前设置构造 Runner。
// 建表失败(如 DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, prov Provisioner, newRunner func(Settings) Runner, deps Deps) *Module {
	ps, err := newPyStore(st)
	if err != nil {
		panic("python: init store: " + err.Error())
	}
	return &Module{ps: ps, prov: prov, deps: deps, mkrun: newRunner}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "python", Name: "Python 项目", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "Python 项目", Icon: "code", Path: "/python"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:python3 不在 PATH 则不允许启用。
func (*Module) HealthCheck() error { return ProvisionAvailable() }

func (m *Module) Routes(r module.Router) {
	r.Get("/projects", m.handleList)                                   // 只读
	r.Post("/projects", m.handleCreate)                                // 写:operator+
	r.Delete("/projects/{id}", m.handleDelete)                         // 危险写:admin + 确认
	r.Get("/projects/{id}/status", m.handleStatus)                     // 只读
	r.Get("/projects/{id}/logs", m.handleLogs)                         // 只读
	r.Post("/projects/{id}/requirements", m.handleInstall)             // 写:operator+
	r.Post("/projects/{id}/{verb:start|stop|restart}", m.handleAction) // 写:operator+(stop 危险)
	r.Get("/settings", m.handleGetSettings)                            // 只读
	r.Put("/settings", m.handlePutSettings)                            // 写:admin
}

type projectRequest struct {
	Name        string `json:"name"`
	Interpreter string `json:"interpreter"` // 解释器版本标识;空则用设置默认
	StartKind   string `json:"start_kind"`  // gunicorn | uvicorn | script
	AppTarget   string `json:"app_target"`  // "module:app" 或脚本相对路径
	Port        int    `json:"port"`
	Workers     int    `json:"workers"`
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	ps, err := m.ps.list()
	if err != nil {
		log.Printf("python: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if ps == nil {
		ps = []Project{}
	}
	writeJSON(w, http.StatusOK, ps)
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req projectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	set, err := m.ps.loadSettings()
	if err != nil {
		log.Printf("python: load settings failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	if req.Interpreter == "" {
		req.Interpreter = set.Interpreter
	}
	if req.Workers == 0 {
		req.Workers = 1
	}
	if !m.validateProject(w, req) {
		return
	}
	// 项目目录与 venv 目录由名称在配置根下派生,名称已过白名单(无路径分隔符),
	// 故 filepath.Join 不会逃逸根目录。
	projectDir := filepath.Join(set.ProjectRoot, req.Name)
	venvDir := filepath.Join(set.VenvRoot, req.Name)

	id, err := m.ps.create(Project{
		Name: req.Name, ProjectDir: projectDir, VenvDir: venvDir,
		Interpreter: req.Interpreter, StartKind: req.StartKind, AppTarget: req.AppTarget,
		Port: req.Port, Workers: req.Workers, CreatedBy: &uid,
	})
	if err != nil {
		http.Error(w, "create failed (duplicate name?)", http.StatusConflict)
		return
	}
	if err := m.prov.CreateVenv(req.Interpreter, venvDir); err != nil {
		_ = m.ps.delete(id) // 回滚元数据:venv 没建成,不留孤儿记录。
		log.Printf("python: create venv failed: %v", err)
		http.Error(w, "create venv failed", http.StatusInternalServerError)
		return
	}
	argv := BuildCommand(ProjectSpec{
		Name: req.Name, ProjectDir: projectDir, VenvDir: venvDir,
		StartKind: req.StartKind, AppTarget: req.AppTarget, Port: req.Port, Workers: req.Workers,
	})
	if err := m.mkrun(set).Apply(req.Name, projectDir, argv); err != nil {
		_ = m.ps.delete(id)
		log.Printf("python: apply runner config failed: %v", err)
		http.Error(w, "apply process config failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "python.create", req.Name, clientIP(r))
	p, _ := m.ps.get(id)
	writeJSON(w, http.StatusCreated, p)
}

// handleDelete 删除项目:进程单元与元数据一并移除,属危险操作,需 admin + 二次确认。
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
	p, err := m.ps.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	set, err := m.ps.loadSettings()
	if err != nil {
		log.Printf("python: load settings failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	rn := m.mkrun(set)
	// 先停再删配置,避免删了配置仍有进程残留。stop 失败不阻断删除(可能本就没起)。
	_, _ = rn.Action("stop", p.Name)
	if err := rn.Remove(p.Name); err != nil {
		log.Printf("python: remove process config failed: %v", err)
		http.Error(w, "remove process config failed", http.StatusInternalServerError)
		return
	}
	if err := m.ps.delete(id); err != nil {
		log.Printf("python: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "python.delete", p.Name, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := m.lookupProject(w, r)
	if !ok {
		return
	}
	out, err := m.runner().Status(p.Name)
	if err != nil {
		log.Printf("python: status failed: %v", err)
		http.Error(w, "status unavailable", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleLogs(w http.ResponseWriter, r *http.Request) {
	p, ok := m.lookupProject(w, r)
	if !ok {
		return
	}
	lines := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lines = n
		}
	}
	out, err := m.runner().Logs(p.Name, lines)
	if err != nil {
		log.Printf("python: logs failed: %v", err)
		http.Error(w, "log unavailable", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

// handleInstall 在项目 venv 内安装 requirements.txt(取项目目录下固定文件名,不接受任意路径)。
func (m *Module) handleInstall(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	p, ok := m.lookupProject(w, r)
	if !ok {
		return
	}
	reqPath := filepath.Join(p.ProjectDir, "requirements.txt")
	if err := m.prov.InstallRequirements(p.VenvDir, reqPath); err != nil {
		m.deps.Audit(&uid, "python.install", p.Name+" failed", clientIP(r))
		log.Printf("python: install requirements failed: %v", err)
		http.Error(w, "install requirements failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "python.install", p.Name+" ok", clientIP(r))
	writePlain(w, "requirements installed")
}

func (m *Module) handleAction(w http.ResponseWriter, r *http.Request) {
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	// stop 会终止运行中的项目进程,属危险操作:需二次确认。
	if verb == "stop" && !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	p, ok := m.lookupProject(w, r)
	if !ok {
		return
	}
	out, err := m.runner().Action(verb, p.Name)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "python."+verb, p.Name+" "+outcome, clientIP(r))
	if err != nil {
		log.Printf("python: %s %q failed: %v", verb, p.Name, err)
		http.Error(w, "process operation failed", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ps.loadSettings()
	if err != nil {
		log.Printf("python: load settings failed: %v", err)
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
	// 路径设置同样防注入:须为绝对路径、无控制字符;解释器须过版本白名单。
	if !ValidDir(set.ProjectRoot) || !ValidDir(set.VenvRoot) || !ValidDir(set.ConfDir) || !ValidDir(set.LogDir) {
		http.Error(w, "project_root, venv_root, conf_dir, log_dir must be absolute paths without control chars", http.StatusBadRequest)
		return
	}
	if !ValidPythonVersion(set.Interpreter) {
		http.Error(w, "invalid interpreter (e.g. python3 / python3.11)", http.StatusBadRequest)
		return
	}
	if err := m.ps.saveSettings(set); err != nil {
		log.Printf("python: save settings failed: %v", err)
		http.Error(w, "save settings failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "python.settings", set.ProjectRoot+" "+set.VenvRoot, clientIP(r))
	writeJSON(w, http.StatusOK, set)
}

// runner 用当前持久化设置构造 Runner(读设置失败时回退默认值)。
func (m *Module) runner() Runner {
	set, err := m.ps.loadSettings()
	if err != nil {
		set = DefaultSettings()
	}
	return m.mkrun(set)
}

// lookupProject 解析 id 并取项目。失败时已写响应,返回 ok=false。
func (m *Module) lookupProject(w http.ResponseWriter, r *http.Request) (Project, bool) {
	id, ok := parseID(w, r)
	if !ok {
		return Project{}, false
	}
	p, err := m.ps.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return Project{}, false
	}
	return p, true
}

// requireWriter 校验 operator/admin 角色。失败时已写响应,返回 ok=false。
func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// requireAdmin 校验 admin 角色。失败时已写响应,返回 ok=false。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

// validateProject 校验创建请求各字段。失败时已写 400,返回 false。
func (m *Module) validateProject(w http.ResponseWriter, req projectRequest) bool {
	if !ValidProjectName(req.Name) {
		http.Error(w, "invalid project name (alnum . _ - only, max 64)", http.StatusBadRequest)
		return false
	}
	if !ValidPythonVersion(req.Interpreter) {
		http.Error(w, "invalid interpreter (e.g. python3 / python3.11)", http.StatusBadRequest)
		return false
	}
	if !ValidStartKind(req.StartKind) {
		http.Error(w, "invalid start_kind (gunicorn | uvicorn | script)", http.StatusBadRequest)
		return false
	}
	if !ValidAppTarget(req.AppTarget) {
		http.Error(w, "invalid app_target (module:app or relative script path)", http.StatusBadRequest)
		return false
	}
	// 脚本方式可不监听端口;gunicorn/uvicorn 必须有合法端口。
	if req.StartKind != StartScript && !ValidPort(req.Port) {
		http.Error(w, "invalid port (1..65535)", http.StatusBadRequest)
		return false
	}
	if req.Workers < 1 || req.Workers > 256 {
		http.Error(w, "invalid workers (1..256)", http.StatusBadRequest)
		return false
	}
	return true
}

func confirmed(r *http.Request) bool {
	return r.Header.Get("X-Confirm-Danger") != ""
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

func writePlain(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte(s))
}

// clientIP 从 RemoteAddr 取 IP(无代理信任,与 server 层一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
