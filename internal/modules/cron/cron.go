// Package cron 实现定时任务模块:管理当前用户的 crontab 托管区,
// 任务元数据(备注/创建人/启停态/最近运行)存自建表。
package cron

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入宿主能力,避免反向依赖 server。与 service 模块一致。
type Deps struct {
	Principal func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit     func(userID *int64, action, detail, ip string)  // 写审计
}

// Module 是可开关的定时任务模块。
type Module struct {
	cs   *cronStore
	deps Deps
}

// New 建表并返回模块。建表失败(如 DB 不可用)直接 panic:模块无法工作。
func New(st *store.Store, deps Deps) *Module {
	cs, err := newCronStore(st)
	if err != nil {
		panic("cron: init store: " + err.Error())
	}
	return &Module{cs: cs, deps: deps}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "cron", Name: "定时任务", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "定时任务", Icon: "clock", Path: "/cron"}}
}

// Start 启用时把已启用任务同步进 crontab 托管区(保持 DB 与 crontab 一致)。
func (m *Module) Start(context.Context) error { return m.syncCrontab() }

// Stop 不清空 crontab:停用模块不应静默删掉用户已生效的定时任务。
func (*Module) Stop(context.Context) error { return nil }

// HealthCheck:crontab 命令不在则不允许启用。
func (*Module) HealthCheck() error { return system.CrontabAvailable() }

func (m *Module) Routes(r module.Router) {
	r.Get("/jobs", m.handleList)                               // 只读
	r.Post("/jobs", m.handleCreate)                            // 写
	r.Put("/jobs/{id}", m.handleUpdate)                        // 写
	r.Delete("/jobs/{id}", m.handleDelete)                     // 写
	r.Post("/jobs/{id}/{verb:enable|disable}", m.handleToggle) // 写
}

type jobRequest struct {
	Expr    string `json:"expr"`
	Command string `json:"command"`
	Comment string `json:"comment"`
	Enabled *bool  `json:"enabled"` // 仅 create 用;nil 默认启用
}

func (m *Module) handleList(w http.ResponseWriter, _ *http.Request) {
	jobs, err := m.cs.list()
	if err != nil {
		log.Printf("cron: list failed: %v", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	if jobs == nil {
		jobs = []Job{}
	}
	writeJSON(w, http.StatusOK, jobs)
}

func (m *Module) handleCreate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	req, ok := decode(w, r)
	if !ok {
		return
	}
	if !validateJob(w, req) {
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	id, err := m.cs.create(Job{
		Expr: strings.TrimSpace(req.Expr), Command: strings.TrimSpace(req.Command),
		Comment: req.Comment, Enabled: enabled, CreatedBy: &uid,
	})
	if err != nil {
		log.Printf("cron: create failed: %v", err)
		http.Error(w, "create failed", http.StatusInternalServerError)
		return
	}
	if err := m.syncCrontab(); err != nil {
		log.Printf("cron: sync after create failed: %v", err)
		http.Error(w, "crontab sync failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "cron.create", strconv.FormatInt(id, 10)+" "+req.Expr, clientIP(r))
	job, _ := m.cs.get(id)
	writeJSON(w, http.StatusCreated, job)
}

func (m *Module) handleUpdate(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	req, ok := decode(w, r)
	if !ok {
		return
	}
	if !validateJob(w, req) {
		return
	}
	if _, err := m.cs.get(id); err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	if err := m.cs.update(id, strings.TrimSpace(req.Expr), strings.TrimSpace(req.Command), req.Comment); err != nil {
		log.Printf("cron: update failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if err := m.syncCrontab(); err != nil {
		log.Printf("cron: sync after update failed: %v", err)
		http.Error(w, "crontab sync failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "cron.update", strconv.FormatInt(id, 10), clientIP(r))
	job, _ := m.cs.get(id)
	writeJSON(w, http.StatusOK, job)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := m.cs.delete(id); err != nil {
		log.Printf("cron: delete failed: %v", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	if err := m.syncCrontab(); err != nil {
		log.Printf("cron: sync after delete failed: %v", err)
		http.Error(w, "crontab sync failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "cron.delete", strconv.FormatInt(id, 10), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleToggle(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := m.cs.get(id); err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	verb := chi.URLParamFromCtx(r.Context(), "verb")
	enable := verb == "enable"
	if err := m.cs.setEnabled(id, enable); err != nil {
		log.Printf("cron: toggle failed: %v", err)
		http.Error(w, "toggle failed", http.StatusInternalServerError)
		return
	}
	if err := m.syncCrontab(); err != nil {
		log.Printf("cron: sync after toggle failed: %v", err)
		http.Error(w, "crontab sync failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "cron."+verb, strconv.FormatInt(id, 10), clientIP(r))
	job, _ := m.cs.get(id)
	writeJSON(w, http.StatusOK, job)
}

// syncCrontab 用所有启用任务重写 crontab 托管区,保留区外用户行。
func (m *Module) syncCrontab() error {
	jobs, err := m.cs.enabled()
	if err != nil {
		return err
	}
	lines := make([]system.CronJobLine, 0, len(jobs))
	for _, j := range jobs {
		lines = append(lines, system.CronJobLine{
			ID: j.ID, Expr: j.Expr, Command: j.Command, Comment: j.Comment,
		})
	}
	existing, err := system.ReadCrontab()
	if err != nil {
		return err
	}
	merged := system.MergeManagedBlock(existing, system.RenderManagedBlock(lines))
	return system.WriteCrontab(merged)
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

// validateJob 校验 cron 表达式与命令。失败时已写 400,返回 false。
func validateJob(w http.ResponseWriter, req jobRequest) bool {
	if !system.ValidCronExpr(req.Expr) {
		http.Error(w, "invalid cron expression (need 5 fields, safe chars only)", http.StatusBadRequest)
		return false
	}
	if !system.ValidCronCommand(req.Command) {
		http.Error(w, "invalid command (no newlines or % allowed)", http.StatusBadRequest)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request) (jobRequest, bool) {
	var req jobRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return jobRequest{}, false
	}
	return req, true
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

// clientIP 从 RemoteAddr 取 IP(与 server 层一致,无代理信任)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
