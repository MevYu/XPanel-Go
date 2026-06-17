// Package malscan 实现木马/webshell 查杀模块:纯 Go 静态特征扫描 web 目录,
// 标记可疑文件、记录命中,支持隔离(移动到隔离区)、移出隔离与加白名单。
// 只读扫描,绝不执行被扫文件;隔离为危险操作,需 admin + 二次确认 + 审计。
package malscan

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的木马查杀模块。
type Module struct {
	ms    *malStore
	deps  Deps
	rules []Rule
}

// New 建表并返回模块。建表失败(如 DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, deps Deps) *Module {
	ms, err := newMalStore(st)
	if err != nil {
		panic("malscan: init store: " + err.Error())
	}
	return &Module{ms: ms, deps: deps, rules: builtinRules}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "malscan", Name: "木马查杀", Category: "安全"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "木马查杀", Icon: "bug", Path: "/malscan"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:纯 Go 实现,无外部依赖,恒可用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/rules", m.handleRules)                // 只读:列出内置规则
	r.Get("/settings", m.handleGetSettings)       // 只读:当前设置(需 admin,见处理)
	r.Put("/settings", m.handlePutSettings)       // 写:改设置,需 admin
	r.Post("/scan", m.handleScan)                 // 写:启动扫描,需 operator+
	r.Get("/tasks", m.handleTasks)                // 只读:扫描任务列表
	r.Get("/tasks/{id}/hits", m.handleHits)       // 只读:某任务命中详情
	r.Get("/quarantine", m.handleQuarantine)      // 只读:隔离区列表
	r.Post("/quarantine", m.handleQuarantineFile) // 危险写:隔离文件,需 admin + 确认
	r.Post("/restore", m.handleRestore)           // 危险写:移出隔离,需 admin + 确认
	r.Post("/delete", m.handleDelete)             // 危险写:直接删除命中文件,需 admin + 确认
	r.Post("/whitelist", m.handleAddWhitelist)    // 写:加白名单,需 operator+
	r.Delete("/whitelist", m.handleDelWhitelist)  // 写:移除白名单,需 operator+
}

func (m *Module) handleRules(w http.ResponseWriter, _ *http.Request) {
	type ruleView struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Score   int    `json:"score"`
		Pattern string `json:"pattern"`
	}
	out := make([]ruleView, 0, len(m.rules))
	for _, r := range m.rules {
		out = append(out, ruleView{r.ID, r.Name, int(r.Score), r.Pattern()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if !m.requireAdmin(w, r) {
		return
	}
	s, err := m.ms.getSettings()
	if err != nil {
		log.Printf("malscan: get settings: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, s)
}

func (m *Module) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	var s Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&s); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validSettings(w, s) {
		return
	}
	if err := m.ms.putSettings(s); err != nil {
		log.Printf("malscan: put settings: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "malscan.settings", s.ScanDir, clientIP(r))
	writeJSON(w, http.StatusOK, s)
}

type scanRequest struct {
	Dir string `json:"dir"` // 可选:扫描子目录(相对 scan_dir),空=扫整个 scan_dir
}

func (m *Module) handleScan(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	var req scanRequest
	_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req)

	s, err := m.ms.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	// 路径穿越防护:req.Dir 限定在 scan_dir 子树内。
	root, err := system.SafeJoin(s.ScanDir, req.Dir)
	if err != nil {
		http.Error(w, "invalid scan dir: "+err.Error(), http.StatusBadRequest)
		return
	}

	wl, err := m.ms.whitelist()
	if err != nil {
		http.Error(w, "whitelist unavailable", http.StatusInternalServerError)
		return
	}
	lim := ScanLimits{MaxFileSize: s.MaxFileSize, MaxFiles: s.MaxFiles, ScoreToFlag: s.ScoreToFlag, MaxLineBytes: 1 << 20}

	taskID, err := m.ms.createTask(root, &uid)
	if err != nil {
		log.Printf("malscan: create task: %v", err)
		http.Error(w, "scan start failed", http.StatusInternalServerError)
		return
	}
	rep, scanErr := scanTree(root, m.rules, lim, func(abs string) bool { return wl[abs] })
	status := "done"
	errStr := ""
	if scanErr != nil {
		status = "failed"
		errStr = scanErr.Error()
		log.Printf("malscan: scan %q failed: %v", root, scanErr)
	} else if err := m.ms.insertHits(taskID, rep.Flagged); err != nil {
		log.Printf("malscan: insert hits: %v", err)
	}
	if err := m.ms.finishTask(taskID, status, rep, errStr); err != nil {
		log.Printf("malscan: finish task: %v", err)
	}
	m.deps.Audit(&uid, "malscan.scan", root+" flagged="+strconv.Itoa(len(rep.Flagged)), clientIP(r))

	task, _ := m.ms.listTaskByID(taskID)
	writeJSON(w, http.StatusOK, task)
}

func (m *Module) handleTasks(w http.ResponseWriter, _ *http.Request) {
	tasks, err := m.ms.listTasks()
	if err != nil {
		log.Printf("malscan: list tasks: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if tasks == nil {
		tasks = []Task{}
	}
	writeJSON(w, http.StatusOK, tasks)
}

func (m *Module) handleHits(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	hits, err := m.ms.listHits(id)
	if err != nil {
		log.Printf("malscan: list hits: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if hits == nil {
		hits = []Hit{}
	}
	writeJSON(w, http.StatusOK, hits)
}

func (m *Module) handleQuarantine(w http.ResponseWriter, _ *http.Request) {
	qs, err := m.ms.listQuarantine()
	if err != nil {
		log.Printf("malscan: list quarantine: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if qs == nil {
		qs = []Quarantine{}
	}
	writeJSON(w, http.StatusOK, qs)
}

type pathRequest struct {
	Path string `json:"path"` // 相对 scan_dir 的路径
}

// handleQuarantineFile 把可疑文件移入隔离区:危险操作,需 admin + 二次确认。
func (m *Module) handleQuarantineFile(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	req, ok := decodePath(w, r)
	if !ok {
		return
	}
	s, err := m.ms.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	abs, err := system.SafeJoin(s.ScanDir, req.Path)
	if err != nil {
		http.Error(w, "invalid path: "+err.Error(), http.StatusBadRequest)
		return
	}
	stored, err := quarantineFile(abs, s.QuarantineDir)
	if err != nil {
		log.Printf("malscan: quarantine %q: %v", abs, err)
		http.Error(w, "quarantine failed", http.StatusInternalServerError)
		return
	}
	if _, err := m.ms.addQuarantine(abs, stored, &uid); err != nil {
		log.Printf("malscan: record quarantine: %v", err)
	}
	_ = m.ms.markQuarantined(abs, true)
	m.deps.Audit(&uid, "malscan.quarantine", abs, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"orig_path": abs, "stored_path": stored})
}

// handleRestore 把文件移出隔离区还原:危险操作,需 admin + 二次确认。
func (m *Module) handleRestore(w http.ResponseWriter, r *http.Request) {
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	req, ok := decodePath(w, r)
	if !ok {
		return
	}
	s, err := m.ms.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	abs, err := system.SafeJoin(s.ScanDir, req.Path)
	if err != nil {
		http.Error(w, "invalid path: "+err.Error(), http.StatusBadRequest)
		return
	}
	q, err := m.ms.activeQuarantine(abs)
	if err != nil {
		http.Error(w, "no active quarantine for path", http.StatusNotFound)
		return
	}
	if err := restoreFile(q.StoredPath, q.OrigPath); err != nil {
		log.Printf("malscan: restore %q: %v", abs, err)
		http.Error(w, "restore failed", http.StatusInternalServerError)
		return
	}
	_ = m.ms.markRestored(q.ID)
	_ = m.ms.markQuarantined(abs, false)
	m.deps.Audit(&uid, "malscan.restore", abs, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"restored": abs})
}

// handleDelete 直接删除命中文件:危险操作,需 admin + 二次确认。
// path 经 SafeJoin 限定在 scan_dir 内,拒绝 ".." 与软链逃逸,绝不动到扫描根之外的文件。
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
	req, ok := decodePath(w, r)
	if !ok {
		return
	}
	s, err := m.ms.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	abs, err := system.SafeJoin(s.ScanDir, req.Path)
	if err != nil {
		http.Error(w, "invalid path: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := os.Remove(abs); err != nil {
		log.Printf("malscan: delete %q: %v", abs, err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "malscan.delete", abs, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"deleted": abs})
}

func (m *Module) handleAddWhitelist(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	abs, ok := m.resolveScanPath(w, r)
	if !ok {
		return
	}
	if err := m.ms.addWhitelist(abs, &uid); err != nil {
		log.Printf("malscan: add whitelist: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "malscan.whitelist.add", abs, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]string{"whitelisted": abs})
}

func (m *Module) handleDelWhitelist(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	abs, ok := m.resolveScanPath(w, r)
	if !ok {
		return
	}
	if err := m.ms.removeWhitelist(abs); err != nil {
		log.Printf("malscan: remove whitelist: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "malscan.whitelist.del", abs, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// resolveScanPath 解码请求路径并 SafeJoin 到 scan_dir,返回绝对路径。失败已写响应。
func (m *Module) resolveScanPath(w http.ResponseWriter, r *http.Request) (string, bool) {
	req, ok := decodePath(w, r)
	if !ok {
		return "", false
	}
	s, err := m.ms.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return "", false
	}
	abs, err := system.SafeJoin(s.ScanDir, req.Path)
	if err != nil {
		http.Error(w, "invalid path: "+err.Error(), http.StatusBadRequest)
		return "", false
	}
	return abs, true
}

// --- helpers ---

func validSettings(w http.ResponseWriter, s Settings) bool {
	if !filepath.IsAbs(s.ScanDir) || !filepath.IsAbs(s.QuarantineDir) {
		http.Error(w, "scan_dir and quarantine_dir must be absolute paths", http.StatusBadRequest)
		return false
	}
	if s.MaxFileSize <= 0 || s.MaxFiles <= 0 || s.ScoreToFlag <= 0 {
		http.Error(w, "max_file_size, max_files, score_to_flag must be positive", http.StatusBadRequest)
		return false
	}
	return true
}

func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	_, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return false
	}
	return true
}

func (m *Module) requireWriter(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" && role != "operator" {
		http.Error(w, "forbidden: requires operator role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func decodePath(w http.ResponseWriter, r *http.Request) (pathRequest, bool) {
	var req pathRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return pathRequest{}, false
	}
	if req.Path == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return pathRequest{}, false
	}
	return req, true
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
