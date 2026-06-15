// Package java 实现 Java 项目管理模块(对标 aaPanel Java):
// 列出/创建/删除/启停重启项目、查看状态与日志,检测已装 JDK 版本。
// 支持两种部署:jar/war 用 java -jar 起独立进程(经 supervisor 守护);
// tomcat 把 war 部署进 Tomcat webapps。项目元数据存自建表,进程/部署副作用经 ProcessManager 抽象。
//
// 安全要点:
//   - 项目名/构件路径/JVM 参数/端口/JDK 版本/部署类型全部白名单校验,非法即拒,绝不拼进配置或 exec 参数。
//   - JVM 参数拆成 exec 参数数组,绝不拼 shell。
//   - 构件路径限定在可配置基目录内,拒绝路径穿越。
//   - 变更需 operator+;删除/停止为危险操作,需 admin + X-Confirm-Danger + 审计。
//   - 可配置路径(项目根基目录/JDK 目录/Tomcat 目录/进程配置目录/日志目录)持久化在 java_settings 表,仅 admin 可改。
package java

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
}

// Settings 是可配置的路径与默认值,持久化在 java_settings 表。
type Settings struct {
	BaseDir   string `json:"base_dir"`   // 项目根基目录,构件路径限定其下
	JDKDir    string `json:"jdk_dir"`    // JDK bin 目录,前置到进程 PATH 并定位 java
	TomcatDir string `json:"tomcat_dir"` // Tomcat 安装目录(含 webapps),war 部署到其下
	ConfDir   string `json:"conf_dir"`   // 进程管理器(supervisor)配置目录
	LogDir    string `json:"log_dir"`    // 项目 stdout/stderr 日志目录
}

// DefaultSettings 返回内置默认值(对标 aaPanel 习惯)。
func DefaultSettings() Settings {
	return Settings{
		BaseDir:   "/www/java",
		JDKDir:    "/usr/lib/jvm/default/bin",
		TomcatDir: "/www/server/tomcat",
		ConfDir:   "/etc/supervisor/conf.d",
		LogDir:    "/www/wwwlogs/java",
	}
}

func (s Settings) validate() error {
	if err := validAbsDir(s.BaseDir); err != nil {
		return err
	}
	if err := validAbsDir(s.JDKDir); err != nil {
		return err
	}
	if err := validAbsDir(s.TomcatDir); err != nil {
		return err
	}
	if err := validAbsDir(s.ConfDir); err != nil {
		return err
	}
	return validAbsDir(s.LogDir)
}

// Module 是可开关的 Java 项目管理模块。进程/部署副作用经 ProcessManager 抽象(可注入 mock)。
type Module struct {
	js   *javaStore
	pm   ProcessManager
	deps Deps
}

// New 建表并返回模块。建表失败直接 panic:模块无法工作。
func New(st *store.Store, pm ProcessManager, deps Deps) *Module {
	js, err := newJavaStore(st)
	if err != nil {
		panic("java: init store: " + err.Error())
	}
	return &Module{js: js, pm: pm, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "java", Name: "Java 项目", Category: "网站"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "Java 项目", Icon: "coffee", Path: "/java"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:java 与进程管理器须可用,否则不允许启用。
func (m *Module) HealthCheck() error { return m.pm.Available() }

func (m *Module) Routes(r module.Router) {
	r.Get("/projects", m.handleList)                                   // 只读
	r.Post("/projects", m.handleCreate)                                // 写:operator+
	r.Delete("/projects/{id}", m.handleDelete)                         // 危险写:admin + 确认
	r.Get("/projects/{id}/status", m.handleStatus)                     // 只读
	r.Get("/projects/{id}/logs", m.handleLogs)                         // 只读
	r.Post("/projects/{id}/{verb:start|stop|restart}", m.handleAction) // 写:operator+(stop 危险)
	r.Get("/versions", m.handleVersions)                               // 只读:已装 JDK 版本
	r.Get("/settings", m.handleGetSettings)                            // 只读
	r.Put("/settings", m.handlePutSettings)                            // 写:admin
}

type projectRequest struct {
	Name         string `json:"name"`
	Type         string `json:"type"`          // jar | war | tomcat
	ArtifactPath string `json:"artifact_path"` // 相对基目录或基目录内绝对路径
	JavaVersion  string `json:"java_version"`
	JVMArgs      string `json:"jvm_args"`
	Port         int    `json:"port"`
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	ps, err := m.js.list()
	if err != nil {
		log.Printf("java: list failed: %v", err)
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
	set, err := m.js.loadSettings()
	if err != nil {
		log.Printf("java: load settings failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	// 严格校验:任一非法即 400,绝不进模板/exec/部署(无审计)。
	if !ValidProjectName(req.Name) {
		http.Error(w, "invalid project name (alnum start, alnum . _ - only, max 64)", http.StatusBadRequest)
		return
	}
	if !ValidProjectType(req.Type) {
		http.Error(w, "invalid type (jar|war|tomcat)", http.StatusBadRequest)
		return
	}
	if !ValidJavaVersion(req.JavaVersion) {
		http.Error(w, "invalid java version", http.StatusBadRequest)
		return
	}
	if !ValidJVMArgs(req.JVMArgs) {
		http.Error(w, "invalid jvm args (single line, no shell metacharacters)", http.StatusBadRequest)
		return
	}
	if !ValidPort(req.Port) {
		http.Error(w, "invalid port (1..65535)", http.StatusBadRequest)
		return
	}
	suffix := ".jar"
	if req.Type == "war" || req.Type == "tomcat" {
		suffix = ".war"
	}
	artifact, err := safeArtifactPath(set.BaseDir, req.ArtifactPath, suffix)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id, err := m.js.create(Project{
		Name: req.Name, Type: req.Type, ArtifactPath: artifact, JavaVersion: req.JavaVersion,
		JVMArgs: req.JVMArgs, Port: req.Port, CreatedBy: &uid,
	})
	if err != nil {
		http.Error(w, "create failed (duplicate name?)", http.StatusConflict)
		return
	}

	if err := m.provision(set, Project{
		Name: req.Name, Type: req.Type, ArtifactPath: artifact, JVMArgs: req.JVMArgs, Port: req.Port,
	}); err != nil {
		_ = m.js.delete(id) // 回滚元数据:副作用没落盘,不留孤儿记录。
		log.Printf("java: provision failed: %v", err)
		http.Error(w, "apply process config failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "java.create", req.Name, clientIP(r))
	p, _ := m.js.get(id)
	writeJSON(w, http.StatusCreated, p)
}

// provision 按部署类型落实副作用:jar/war 写 supervisor 配置;tomcat 部署 war。
func (m *Module) provision(set Settings, p Project) error {
	if p.Type == "tomcat" {
		return m.pm.Deploy(set.TomcatDir, p.Name, p.ArtifactPath)
	}
	return m.pm.Apply(set.ConfDir, ProcessSpec{
		Name: p.Name, ArtifactPath: p.ArtifactPath, JVMArgs: p.JVMArgs, Port: p.Port,
		JavaPath: set.JDKDir, LogDir: set.LogDir,
	})
}

// handleDelete 删除项目:停进程/下线 war,删配置与元数据。危险操作,需 admin + 二次确认。
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
	p, err := m.js.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	set, err := m.js.loadSettings()
	if err != nil {
		log.Printf("java: load settings failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if err := m.deprovision(set, p); err != nil {
		log.Printf("java: deprovision failed: %v", err)
		http.Error(w, "remove config failed", http.StatusInternalServerError)
		return
	}
	if err := m.js.delete(id); err != nil {
		log.Printf("java: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "java.delete", p.Name, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// deprovision 撤销 provision 的副作用。tomcat 下线 war;jar/war 先停进程再删配置。
func (m *Module) deprovision(set Settings, p Project) error {
	if p.Type == "tomcat" {
		return m.pm.Undeploy(set.TomcatDir, p.Name)
	}
	// 先停再删配置,避免删了配置仍有进程残留。stop 失败不阻断删除(可能本就没起)。
	_, _ = m.pm.Action("stop", p.Name)
	return m.pm.Remove(set.ConfDir, p.Name)
}

func (m *Module) handleStatus(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	p, err := m.js.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	out, err := m.pm.Status(p.Name)
	if err != nil {
		log.Printf("java: status failed: %v", err)
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
	p, err := m.js.get(id)
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
		log.Printf("java: tail log failed: %v", err)
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
	p, err := m.js.get(id)
	if err != nil {
		http.Error(w, "project not found", http.StatusNotFound)
		return
	}
	out, err := m.pm.Action(verb, p.Name)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, "java."+verb, p.Name+" "+outcome, clientIP(r))
	if err != nil {
		log.Printf("java: %s %q failed: %v", verb, p.Name, err)
		http.Error(w, "process operation failed", http.StatusInternalServerError)
		return
	}
	writePlain(w, out)
}

func (m *Module) handleVersions(w http.ResponseWriter, _ *http.Request) {
	vs := m.pm.JavaVersions()
	if vs == nil {
		vs = []string{}
	}
	writeJSON(w, http.StatusOK, vs)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, _ *http.Request) {
	set, err := m.js.loadSettings()
	if err != nil {
		log.Printf("java: load settings failed: %v", err)
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
	if err := m.js.saveSettings(set); err != nil {
		log.Printf("java: save settings failed: %v", err)
		http.Error(w, "save settings failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "java.settings", set.BaseDir+" "+set.JDKDir, clientIP(r))
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

// clientIP 从 RemoteAddr 取 IP(无代理信任,与 server 层一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
