// Package antitamper 实现文件防篡改模块:对受保护目录建立 SHA-256 基线,
// 后台周期扫描检出新增/删除/修改并记篡改事件。只读监控,绝不执行被监控文件;
// 路径限定在受保护目录子树内并经穿越防护(SafeJoin)。变更需 admin 并审计。
package antitamper

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
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入宿主能力,避免反向依赖 server。与其它模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的文件防篡改模块。
type Module struct {
	as   *atStore
	mon  *monitor
	deps Deps
}

// New 建表并返回模块。建表失败(如 DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, deps Deps) *Module {
	as, err := newATStore(st)
	if err != nil {
		panic("antitamper: init store: " + err.Error())
	}
	m := &Module{as: as, deps: deps}
	// 告警 hook 暂只写日志;落地告警渠道由后续接入。
	m.mon = newMonitor(as, func(c Change) {
		log.Printf("antitamper: ALERT %s %s", c.Type, c.Path)
	})
	return m
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "antitamper", Name: "防篡改", Category: "安全"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "防篡改", Icon: "file-lock", Path: "/antitamper"}}
}

// Start 起后台监控 goroutine 并立即返回(循环跑在 goroutine 内)。
func (m *Module) Start(ctx context.Context) error {
	m.mon.start(ctx)
	return nil
}

// Stop 取消监控 ctx 并等待 goroutine 干净退出(无泄漏)。
func (m *Module) Stop(context.Context) error {
	m.mon.stop()
	return nil
}

// HealthCheck:纯 Go 实现,无外部依赖,恒可用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // 只读:当前设置(需 admin)
	r.Put("/settings", m.handlePutSettings) // 写:改设置,需 admin

	r.Get("/events", m.handleListEvents) // 只读:篡改事件列表

	r.Post("/baseline", m.handleRebuild) // 写:重建基线,需 admin
	r.Get("/baseline", m.handleBaseline) // 只读:当前基线摘要(文件数)

	r.Post("/{verb:pause|resume}", m.handleToggle) // 写:暂停/恢复保护,需 admin
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

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	s, err := m.as.getSettings()
	if err != nil {
		log.Printf("antitamper: get settings: %v", err)
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&s); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validSettings(w, s) {
		return
	}
	if err := m.as.putSettings(s); err != nil {
		log.Printf("antitamper: put settings: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "antitamper.settings", strconv.Itoa(len(s.ProtectedDirs))+" dirs", clientIP(r))
	writeJSON(w, http.StatusOK, s)
}

func (m *Module) handleListEvents(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil {
			limit = n
		}
	}
	evs, err := m.as.listEvents(limit)
	if err != nil {
		log.Printf("antitamper: list events: %v", err)
		http.Error(w, "events unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, orEmptyEvents(evs))
}

// handleRebuild 重建基线:扫描所有受保护目录的当前指纹并全量替换基线。
func (m *Module) handleRebuild(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	s, err := m.as.getSettings()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return
	}
	states, err := scanDirs(s.ProtectedDirs, s.ExcludeRules)
	if err != nil {
		log.Printf("antitamper: rebuild scan: %v", err)
		http.Error(w, "scan failed", http.StatusInternalServerError)
		return
	}
	if err := m.as.replaceBaseline(states); err != nil {
		log.Printf("antitamper: rebuild save: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "antitamper.baseline.rebuild", strconv.Itoa(len(states))+" files", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"files": len(states)})
}

func (m *Module) handleBaseline(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	base, err := m.as.baseline()
	if err != nil {
		http.Error(w, "baseline unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"files": len(base)})
}

// handleToggle 暂停/恢复保护(暂停时后台扫描跳过对比/记事件)。
func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	paused := verb == "pause"
	if err := m.as.setPaused(paused); err != nil {
		log.Printf("antitamper: set paused: %v", err)
		http.Error(w, "save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "antitamper."+verb, "", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"paused": paused})
}

// scanDirs 扫描多个受保护目录,合并指纹。各目录须为已存在的绝对路径,
// 经 SafeJoin(dir, ".") 确认目录自身不经符号链接逃逸自身根。
func scanDirs(dirs, exclude []string) (map[string]FileState, error) {
	all := map[string]FileState{}
	for _, dir := range dirs {
		// SafeJoin 以 dir 为根、"." 为相对路径,校验 dir 已存在且未经软链逃逸。
		if _, err := system.SafeJoin(dir, "."); err != nil {
			return nil, err
		}
		states, err := ScanTree(dir, exclude)
		if err != nil {
			return nil, err
		}
		for p, st := range states {
			all[p] = st
		}
	}
	return all, nil
}

// validSettings 校验设置:受保护目录须为绝对且干净路径,间隔须正。失败时已写 400。
func validSettings(w http.ResponseWriter, s Settings) bool {
	if s.IntervalSec <= 0 {
		http.Error(w, "interval_sec must be positive", http.StatusBadRequest)
		return false
	}
	for _, dir := range s.ProtectedDirs {
		if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
			http.Error(w, "protected dir must be an absolute, clean path", http.StatusBadRequest)
			return false
		}
	}
	return true
}

func orEmptyEvents(e []Event) []Event {
	if e == nil {
		return []Event{}
	}
	return e
}

// writeJSON 写 JSON 响应。编码失败仅记录(响应头已发,无法改状态码)。
func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("antitamper: encode response: %v", err)
	}
}

// clientIP 从 RemoteAddr 取 IP(无代理信任,与 server 层一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
