// Package cron 实现定时任务模块:对照 aaPanel 计划任务,支持多种任务类型
// (Shell 脚本/释放内存/日志切割/访问 URL/裸命令,预留站点与数据库备份)、
// 友好的周期选择(落成 cron 表达式存库)、进程内调度执行并保存每次执行日志
// (输出/退出码/耗时),以及立即执行/启停/编辑/删除。
//
// 调度与执行在进程内完成(crontab 自身无法记录每次执行结果);同时仍维护用户
// crontab 的托管区以便外部可见。
package cron

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/module"
	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
)

// Deps 注入宿主能力,避免反向依赖 server。与 service 模块一致。
// BackupSite/BackupDB 是可选的进程内备份钩子:nil 表示未接通(对应任务执行时明确报错)。
// 用钩子而非直接 import sites/database,保持模块解耦。
type Deps struct {
	Principal  func(*http.Request) (userID int64, role string) // 取当前登录主体
	Audit      func(userID *int64, action, detail, ip string)  // 写审计
	ClientIP   func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
	BackupSite func(target string) error                       // backup_site:target 为站点名
	BackupDB   func(target string) error                       // backup_db:target 为 "<engine>:<database>"
}

// logCutRoot 是日志切割任务的路径限定根:log_cut 的 path 经 SafeJoin 限定其下。
const logCutRoot = "/var/log"

// Module 是可开关的定时任务模块。
type Module struct {
	cs    *cronStore
	deps  Deps
	run   *execRunner // 真实执行器;备份钩子可经 SetBackupHooks 后补
	sched *scheduler
}

// New 建表并返回模块。建表失败(如 DB 不可用)直接 panic:模块无法工作。
// 签名保持不变(st, deps)。
func New(st *store.Store, deps Deps) *Module {
	cs, err := newCronStore(st)
	if err != nil {
		panic("cron: init store: " + err.Error())
	}
	r := &execRunner{
		logCutRoot: logCutRoot,
		scriptDir:  filepath.Join(os.TempDir(), "xpanel-cron-scripts"),
		backupSite: deps.BackupSite,
		backupDB:   deps.BackupDB,
	}
	return &Module{cs: cs, deps: deps, run: r, sched: newScheduler(cs, r)}
}

// SetBackupHooks 注入备份钩子。宿主在 sites/database 模块构造后调用一次
// (cron 比它们先构造,故 New 时钩子可能为 nil)。nil 参数保持未接通。
func (m *Module) SetBackupHooks(site, db func(target string) error) {
	if site != nil {
		m.run.backupSite = site
	}
	if db != nil {
		m.run.backupDB = db
	}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "cron", Name: "定时任务", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "定时任务", Icon: "clock", Path: "/cron"}}
}

// Start 启用时同步 crontab 托管区并启动进程内调度器。
func (m *Module) Start(context.Context) error {
	m.sched.start()
	return m.syncCrontab()
}

// Stop 停止调度器;不清空 crontab:停用模块不应静默删掉用户已生效的定时任务。
func (m *Module) Stop(context.Context) error {
	m.sched.stopLoop()
	return nil
}

// HealthCheck:crontab 命令不在则不允许启用。
func (*Module) HealthCheck() error { return system.CrontabAvailable() }

func (m *Module) Routes(r module.Router) {
	r.Get("/jobs", m.handleList)                               // 只读
	r.Get("/jobs/{id}/runs", m.handleRuns)                     // 只读:执行日志
	r.Post("/jobs", m.handleCreate)                            // 写
	r.Put("/jobs/{id}", m.handleUpdate)                        // 写
	r.Delete("/jobs/{id}", m.handleDelete)                     // 写
	r.Post("/jobs/{id}/run", m.handleRunNow)                   // 写:立即执行
	r.Post("/jobs/{id}/{verb:enable|disable}", m.handleToggle) // 写
}

// jobRequest 是 create/update 的请求体。Schedule 与 Type/Payload 描述任务。
// 兼容旧客户端:若 Schedule.Kind 空且给了顶层 Expr,按 raw 处理;
// 若 Type 空且给了顶层 Command,按 command 类型处理。
type jobRequest struct {
	Schedule Schedule `json:"schedule"`
	Type     string   `json:"type"`
	Payload  payload  `json:"payload"`
	Comment  string   `json:"comment"`
	Enabled  *bool    `json:"enabled"` // 仅 create 用;nil 默认启用

	// 旧字段(向后兼容)。
	Expr    string `json:"expr"`
	Command string `json:"command"`
}

// resolve 把请求(含兼容字段)归一成 (expr, type, validated payload)。
func (req jobRequest) resolve() (expr, typ string, p payload, err error) {
	sched := req.Schedule
	if sched.Kind == "" && strings.TrimSpace(req.Expr) != "" {
		sched = Schedule{Kind: schedRaw, Expr: req.Expr}
	}
	expr, err = sched.Build()
	if err != nil {
		return "", "", payload{}, err
	}

	typ = req.Type
	in := req.Payload
	if typ == "" {
		typ = taskCommand
		if in.Command == "" {
			in.Command = req.Command
		}
	}
	if !validTaskType(typ) {
		return "", "", payload{}, errInvalid("unknown task type")
	}
	p, err = validatePayload(typ, in, logCutRoot)
	if err != nil {
		return "", "", payload{}, err
	}
	return expr, typ, p, nil
}

// errInvalid 是校验错误的简单封装,handler 据此回 400。
type validationError struct{ msg string }

func (e validationError) Error() string { return e.msg }
func errInvalid(msg string) error       { return validationError{msg} }

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

func (m *Module) handleRuns(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	limit := maxRunsPerJob
	if q := r.URL.Query().Get("limit"); q != "" {
		if n, err := strconv.Atoi(q); err == nil && n > 0 {
			limit = n
		}
	}
	runs, err := m.cs.runs(id, limit)
	if err != nil {
		log.Printf("cron: runs failed: %v", err)
		http.Error(w, "runs failed", http.StatusInternalServerError)
		return
	}
	if runs == nil {
		runs = []runRecord{}
	}
	writeJSON(w, http.StatusOK, runs)
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
	expr, typ, p, err := req.resolve()
	if err != nil {
		http.Error(w, "invalid job: "+err.Error(), http.StatusBadRequest)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	id, err := m.cs.create(Job{
		Expr: expr, Type: typ, Payload: p, Command: derivedCommand(typ, p),
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
	m.deps.Audit(&uid, "cron.create", strconv.FormatInt(id, 10)+" "+typ+" "+expr, m.clientIP(r))
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
	expr, typ, p, err := req.resolve()
	if err != nil {
		http.Error(w, "invalid job: "+err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := m.cs.get(id); err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	if err := m.cs.update(id, Job{
		Expr: expr, Type: typ, Payload: p, Command: derivedCommand(typ, p), Comment: req.Comment,
	}); err != nil {
		log.Printf("cron: update failed: %v", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	if err := m.syncCrontab(); err != nil {
		log.Printf("cron: sync after update failed: %v", err)
		http.Error(w, "crontab sync failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "cron.update", strconv.FormatInt(id, 10), m.clientIP(r))
	job, _ := m.cs.get(id)
	writeJSON(w, http.StatusOK, job)
}

func (m *Module) handleDelete(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	if !m.requireDangerConfirm(w, r) {
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
	m.deps.Audit(&uid, "cron.delete", strconv.FormatInt(id, 10), m.clientIP(r))
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
	m.deps.Audit(&uid, "cron."+verb, strconv.FormatInt(id, 10), m.clientIP(r))
	job, _ := m.cs.get(id)
	writeJSON(w, http.StatusOK, job)
}

// handleRunNow 立即同步执行一次任务并记录,返回本次执行结果。
func (m *Module) handleRunNow(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireWriter(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	job, err := m.cs.get(id)
	if err != nil {
		http.Error(w, "job not found", http.StatusNotFound)
		return
	}
	res := m.sched.run.run(r.Context(), job)
	if err := m.cs.recordRun(id, res); err != nil {
		log.Printf("cron: record run-now failed: %v", err)
	}
	m.deps.Audit(&uid, "cron.run", strconv.FormatInt(id, 10), m.clientIP(r))
	writeJSON(w, http.StatusOK, runRecord{
		JobID: id, StartedAt: res.StartedAt, DurationMs: res.DurationMs,
		ExitCode: res.ExitCode, Output: res.Output, Err: res.Err,
	})
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

// requireDangerConfirm 对危险操作要求 admin + X-Confirm-Danger 头。
func (m *Module) requireDangerConfirm(w http.ResponseWriter, r *http.Request) bool {
	_, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return false
	}
	if r.Header.Get("X-Confirm-Danger") == "" {
		http.Error(w, "missing X-Confirm-Danger header", http.StatusPreconditionRequired)
		return false
	}
	return true
}

func decode(w http.ResponseWriter, r *http.Request) (jobRequest, bool) {
	var req jobRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024)).Decode(&req); err != nil {
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
