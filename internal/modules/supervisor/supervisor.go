// Package supervisor 实现进程守护模块:管理常驻进程(守护程序),
// 元数据存自建表,真实启停查/日志经 supervisorctl,配置由模板生成写入 conf.d。
package supervisor

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

// Module 是可开关的进程守护模块。
type Module struct {
	ss   *supStore
	ctl  Controller
	deps Deps
}

// New 建表并返回模块。建表失败(如 DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, ctl Controller, deps Deps) *Module {
	ss, err := newSupStore(st)
	if err != nil {
		panic("supervisor: init store: " + err.Error())
	}
	return &Module{ss: ss, ctl: ctl, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "supervisor", Name: "进程守护", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "进程守护", Icon: "activity", Path: "/supervisor"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:supervisorctl 不可用则不允许启用。
func (m *Module) HealthCheck() error { return m.ctl.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/programs", m.handleList)                                   // 只读
	r.Post("/programs", m.handleCreate)                                // 写:admin(可指定任意启动命令 → 提权风险)
	r.Put("/programs/{id}", m.handleUpdate)                            // 写:admin(同 create,可改启动命令 → 提权风险)
	r.Delete("/programs/{id}", m.handleDelete)                         // 危险写:admin + 确认
	r.Get("/programs/{id}/status", m.handleStatus)                     // 只读
	r.Get("/programs/{id}/logs", m.handleLogs)                         // 只读
	r.Post("/programs/{id}/{verb:start|stop|restart}", m.handleAction) // 写:operator+(stop 危险)
	r.Get("/settings", m.handleGetSettings)                            // 只读
	r.Put("/settings", m.handlePutSettings)                            // 写:admin
}

type programRequest struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Directory   string `json:"directory"`
	AutoRestart bool   `json:"auto_restart"`
	Numprocs    int    `json:"numprocs"`
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	ps, err := m.ss.list()
	if err != nil {
		log.Printf("supervisor: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if ps == nil {
		ps = []Program{}
	}
	writeJSON(w, http.StatusOK, ps)
}

// handleCreate 添加守护程序:可指定任意启动命令,该命令以 supervisor 属主(通常 root)执行,
// 故须 admin —— operator 不得借此定义任意命令获得提权。start/stop/restart 等不定义新命令的操作仍是 operator+。
func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var req programRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Numprocs == 0 {
		req.Numprocs = 1
	}
	if !m.validateProgram(w, req) {
		return
	}
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("supervisor: load settings failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	id, err := m.ss.create(Program{
		Name: req.Name, Command: req.Command, Directory: req.Directory,
		AutoRestart: req.AutoRestart, Numprocs: req.Numprocs, CreatedBy: &uid,
	})
	if err != nil {
		// 名称唯一约束冲突等。
		http.Error(w, "create failed (duplicate name?)", http.StatusConflict)
		return
	}
	cfg := RenderConfig(ProgramSpec{
		Name: req.Name, Command: req.Command, Directory: req.Directory,
		AutoRestart: req.AutoRestart, Numprocs: req.Numprocs, LogDir: set.LogDir,
	})
	if err := m.ctl.WriteConfig(set.ConfDir, req.Name, cfg); err != nil {
		_ = m.ss.delete(id) // 回滚元数据:配置没落盘,不留孤儿记录。
		log.Printf("supervisor: write config failed: %v", err)
		http.Error(w, "write config failed", http.StatusInternalServerError)
		return
	}
	if err := m.ctl.Reload(); err != nil {
		log.Printf("supervisor: reload after create failed: %v", err)
		http.Error(w, "supervisor reload failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "supervisor.create", req.Name, m.clientIP(r))
	p, _ := m.ss.get(id)
	writeJSON(w, http.StatusCreated, p)
}

// handleUpdate 编辑守护程序:与 create 同样可指定任意启动命令(以 supervisor 属主执行),
// 故同样须 admin。重写配置并 reload;改名时先删旧配置文件避免留孤儿。
func (m *Module) handleUpdate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var req programRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if req.Numprocs == 0 {
		req.Numprocs = 1
	}
	if !m.validateProgram(w, req) {
		return
	}
	old, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "program not found", http.StatusNotFound)
		return
	}
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("supervisor: load settings failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if err := m.ss.update(Program{
		ID: id, Name: req.Name, Command: req.Command, Directory: req.Directory,
		AutoRestart: req.AutoRestart, Numprocs: req.Numprocs,
	}); err != nil {
		// 改名撞上已存在的程序名(UNIQUE 约束)。
		http.Error(w, "update failed (duplicate name?)", http.StatusConflict)
		return
	}
	cfg := RenderConfig(ProgramSpec{
		Name: req.Name, Command: req.Command, Directory: req.Directory,
		AutoRestart: req.AutoRestart, Numprocs: req.Numprocs, LogDir: set.LogDir,
	})
	if err := m.ctl.WriteConfig(set.ConfDir, req.Name, cfg); err != nil {
		_ = m.ss.update(old) // 回滚元数据:配置没落盘,不留与配置不符的记录。
		log.Printf("supervisor: write config failed: %v", err)
		http.Error(w, "write config failed", http.StatusInternalServerError)
		return
	}
	// 改名后旧配置文件成孤儿:先停旧程序再删旧配置。失败不阻断(可能本就没起)。
	if req.Name != old.Name {
		_, _ = m.ctl.Action("stop", old.Name)
		if err := m.ctl.RemoveConfig(set.ConfDir, old.Name); err != nil {
			log.Printf("supervisor: remove old config %q failed: %v", old.Name, err)
		}
	}
	if err := m.ctl.Reload(); err != nil {
		log.Printf("supervisor: reload after update failed: %v", err)
		http.Error(w, "supervisor reload failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "supervisor.update", req.Name, m.clientIP(r))
	p, _ := m.ss.get(id)
	writeJSON(w, http.StatusOK, p)
}

// handleDelete 删除守护程序:配置与元数据一并移除,属危险操作,需 admin + 二次确认。
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
	p, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "program not found", http.StatusNotFound)
		return
	}
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("supervisor: load settings failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	// 先停再删配置,避免删了配置仍有进程残留。stop 失败不阻断删除(可能本就没起)。
	_, _ = m.ctl.Action("stop", p.Name)
	if err := m.ctl.RemoveConfig(set.ConfDir, p.Name); err != nil {
		log.Printf("supervisor: remove config failed: %v", err)
		http.Error(w, "remove config failed", http.StatusInternalServerError)
		return
	}
	if err := m.ss.delete(id); err != nil {
		log.Printf("supervisor: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if err := m.ctl.Reload(); err != nil {
		log.Printf("supervisor: reload after delete failed: %v", err)
		http.Error(w, "supervisor reload failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "supervisor.delete", p.Name, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	p, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "program not found", http.StatusNotFound)
		return
	}
	out, err := m.ctl.Status(p.Name)
	if err != nil {
		log.Printf("supervisor: status failed: %v", err)
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
	p, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "program not found", http.StatusNotFound)
		return
	}
	lines := 200
	if v := r.URL.Query().Get("tail"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lines = n
		}
	}
	stderr := r.URL.Query().Get("stream") == "stderr"
	out, err := m.ctl.TailLog(p.Name, lines, stderr)
	if err != nil {
		log.Printf("supervisor: tail log failed: %v", err)
		http.Error(w, "log unavailable", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleAction(w http.ResponseWriter, r *http.Request) {
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	// stop 会终止运行中的守护进程,属危险操作:需二次确认。
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
	p, err := m.ss.get(id)
	if err != nil {
		http.Error(w, "program not found", http.StatusNotFound)
		return
	}
	out, err := m.ctl.Action(verb, p.Name)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "supervisor."+verb, p.Name+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("supervisor: %s %q failed: %v", verb, p.Name, err)
		http.Error(w, "supervisor operation failed", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.ss.loadSettings()
	if err != nil {
		log.Printf("supervisor: load settings failed: %v", err)
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
	// 路径设置同样防注入:须为绝对路径、无控制字符。
	if !ValidDir(set.ConfDir) || !ValidDir(set.LogDir) {
		http.Error(w, "conf_dir and log_dir must be absolute paths without control chars", http.StatusBadRequest)
		return
	}
	if err := m.ss.saveSettings(set); err != nil {
		log.Printf("supervisor: save settings failed: %v", err)
		http.Error(w, "save settings failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "supervisor.settings", set.ConfDir+" "+set.LogDir, m.clientIP(r))
	writeJSON(w, http.StatusOK, set)
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

// validateProgram 校验程序名/命令/目录/进程数。失败时已写 400,返回 false。
func (m *Module) validateProgram(w http.ResponseWriter, req programRequest) bool {
	if !ValidProgramName(req.Name) {
		http.Error(w, "invalid program name (alnum . _ - only, max 64)", http.StatusBadRequest)
		return false
	}
	if !ValidCommand(req.Command) {
		http.Error(w, "invalid command (non-empty, no control chars)", http.StatusBadRequest)
		return false
	}
	if !ValidDir(req.Directory) {
		http.Error(w, "invalid directory (must be absolute path)", http.StatusBadRequest)
		return false
	}
	if !ValidNumprocs(req.Numprocs) {
		http.Error(w, "invalid numprocs (1..256)", http.StatusBadRequest)
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
