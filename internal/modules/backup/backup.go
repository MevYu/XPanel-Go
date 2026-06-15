// Package backup 实现备份模块:本地打包(tar.gz)+ 云存储(rclone remote)、
// 备份策略元数据(频率/保留份数)、立即执行、清理过期、从本地/远端恢复。
// 远端凭证 AES-GCM 加密落库;路径经 SafeJoin 限定;删除/恢复需 admin + X-Confirm-Danger + 审计。
package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

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

// Module 是可开关的备份模块。
type Module struct {
	bs   *backupStore
	deps Deps

	arc archiver
	dmp dumper
	rc  rcloneRunner
}

// New 建表并返回模块。secret 用于派生远端凭证的 AES-GCM 密钥。
// 建表/派生失败直接 panic:模块无法工作。
func New(secret string, st *store.Store, deps Deps) *Module {
	cryp, err := newCryptor(secret)
	if err != nil {
		panic("backup: init cryptor: " + err.Error())
	}
	bs, err := newBackupStore(st, cryp)
	if err != nil {
		panic("backup: init store: " + err.Error())
	}
	return &Module{
		bs:   bs,
		deps: deps,
		arc:  tarArchiver{},
		dmp:  cmdDumper{},
		rc:   cmdRclone{},
	}
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "backup", Name: "备份", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "备份", Icon: "archive", Path: "/backup"}}
}

func (*Module) Start(context.Context) error { return nil }
func (*Module) Stop(context.Context) error  { return nil }

// HealthCheck:本地备份不依赖外部命令(archive/tar+gzip 为 stdlib);
// rclone/mysqldump 缺失只影响对应功能,运行时报错,不阻止启用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // admin 只读
	r.Put("/settings", m.handlePutSettings) // admin 写

	r.Get("/remotes", m.handleListRemotes)            // admin
	r.Post("/remotes", m.handleAddRemote)             // admin
	r.Delete("/remotes/{id}", m.handleDeleteRemote)   // admin
	r.Get("/remotes/{id}/files", m.handleRemoteFiles) // admin:列远端备份

	r.Get("/jobs", m.handleListJobs)          // admin
	r.Post("/jobs", m.handleAddJob)           // admin
	r.Delete("/jobs/{id}", m.handleDeleteJob) // admin
	r.Post("/jobs/{id}/prune", m.handlePrune) // admin:按保留份数清理过期本地备份

	r.Get("/records", m.handleListRecords) // admin
	r.Post("/run", m.handleRun)            // admin:立即执行一次备份

	r.Post("/records/{id}/restore", m.handleRestore) // 危险:admin + X-Confirm-Danger
	r.Delete("/records/{id}", m.handleDeleteRecord)  // 危险:admin + X-Confirm-Danger
}

// requireAdmin 统一管理员门;非 admin 返回 false 并已写响应。
func (m *Module) requireAdmin(w http.ResponseWriter, r *http.Request) (int64, bool) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return 0, false
	}
	return uid, true
}

func confirmed(r *http.Request) bool { return r.Header.Get("X-Confirm-Danger") != "" }

// --- settings ---

func (m *Module) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	s, err := m.bs.settings()
	if err != nil {
		log.Printf("backup: settings load failed: %v", err)
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
	var in Settings
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if err := validateSettings(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := m.bs.saveSettings(in); err != nil {
		log.Printf("backup: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "backup.settings.update", "", clientIP(r))
	s, _ := m.bs.settings()
	writeJSON(w, http.StatusOK, s)
}

// --- remotes ---

func (m *Module) handleListRemotes(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	list, err := m.bs.listRemotes()
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) handleAddRemote(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in Remote
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validRemoteName(in.Name) {
		http.Error(w, "invalid remote name", http.StatusBadRequest)
		return
	}
	if in.Type == "" {
		http.Error(w, "remote type required", http.StatusBadRequest)
		return
	}
	if err := validateRemote(in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	saved, err := m.bs.addRemote(in)
	if err != nil {
		log.Printf("backup: add remote failed: %v", err)
		http.Error(w, "add remote failed", http.StatusConflict)
		return
	}
	// 把 remote 写入 rclone 配置(凭证从落库解密;失败不致命,记录日志)。
	if dec, derr := m.bs.getRemote(saved.ID); derr == nil {
		if cerr := m.rc.configCreate(dec); cerr != nil {
			log.Printf("backup: rclone config create %q failed: %v", saved.Name, cerr)
		}
	}
	m.deps.Audit(&uid, "backup.remote.add", saved.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, saved)
}

func (m *Module) handleDeleteRemote(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rem, err := m.bs.getRemote(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := m.bs.deleteRemote(id); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	_ = m.rc.configDelete(rem.Name)
	m.deps.Audit(&uid, "backup.remote.delete", rem.Name, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleRemoteFiles(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rem, err := m.bs.getRemote(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	files, err := m.rc.list(rem)
	if err != nil {
		log.Printf("backup: rclone list %q failed: %v", rem.Name, err)
		http.Error(w, "remote list failed", http.StatusBadGateway)
		return
	}
	writeJSON(w, http.StatusOK, orEmpty(files))
}

// --- jobs ---

func (m *Module) handleListJobs(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	list, err := m.bs.listJobs()
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) handleAddJob(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in Job
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if !validTargetKind(in.TargetKind) {
		http.Error(w, "invalid target_kind", http.StatusBadRequest)
		return
	}
	if in.Target == "" {
		http.Error(w, "target required", http.StatusBadRequest)
		return
	}
	if in.RemoteID != nil {
		if _, err := m.bs.getRemote(*in.RemoteID); err != nil {
			http.Error(w, "unknown remote_id", http.StatusBadRequest)
			return
		}
	}
	saved, err := m.bs.addJob(in)
	if err != nil {
		http.Error(w, "add job failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "backup.job.add", saved.Name, clientIP(r))
	writeJSON(w, http.StatusCreated, saved)
}

func (m *Module) handleDeleteJob(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if _, err := m.bs.getJob(id); err != nil {
		http.NotFound(w, r)
		return
	}
	if err := m.bs.deleteJob(id); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "backup.job.delete", strconv.FormatInt(id, 10), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// handlePrune 按 job 的保留份数清理过期本地备份(删文件 + 删记录)。
func (m *Module) handlePrune(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	job, err := m.bs.getJob(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	stale, err := m.bs.staleLocalRecords(id, job.Keep)
	if err != nil {
		http.Error(w, "prune failed", http.StatusInternalServerError)
		return
	}
	s, _ := m.bs.settings()
	removed := 0
	for _, rec := range stale {
		path, perr := system.SafeJoin(s.BackupDir, rec.Filename)
		if perr == nil {
			_ = os.Remove(path)
		}
		if derr := m.bs.deleteRecord(rec.ID); derr == nil {
			removed++
		}
	}
	m.deps.Audit(&uid, "backup.job.prune", fmt.Sprintf("%s removed=%d", job.Name, removed), clientIP(r))
	writeJSON(w, http.StatusOK, map[string]int{"removed": removed})
}

// --- records ---

func (m *Module) handleListRecords(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	var jobID *int64
	if q := r.URL.Query().Get("job_id"); q != "" {
		if v, err := strconv.ParseInt(q, 10, 64); err == nil {
			jobID = &v
		}
	}
	list, err := m.bs.listRecords(jobID)
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

// runRequest 是 POST /run 的请求体:可指定已存在 job,或一次性指定 target。
type runRequest struct {
	JobID      *int64 `json:"job_id"`      // 非空则用 job 的目标与远端
	TargetKind string `json:"target_kind"` // job_id 为空时必填
	Target     string `json:"target"`
	RemoteID   *int64 `json:"remote_id"` // 可选:备份后上传
}

func (m *Module) handleRun(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in runRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	var jobID *int64
	kind, target := in.TargetKind, in.Target
	remoteID := in.RemoteID
	if in.JobID != nil {
		job, err := m.bs.getJob(*in.JobID)
		if err != nil {
			http.Error(w, "unknown job_id", http.StatusBadRequest)
			return
		}
		jobID, kind, target, remoteID = &job.ID, job.TargetKind, job.Target, job.RemoteID
	}
	if !validTargetKind(kind) || target == "" {
		http.Error(w, "invalid backup target", http.StatusBadRequest)
		return
	}

	rec, err := m.runBackup(jobID, kind, target, remoteID)
	if err != nil {
		log.Printf("backup: run failed: %v", err)
		http.Error(w, "backup failed: "+safeErr(err), http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "backup.run", fmt.Sprintf("%s:%s -> %s", kind, target, rec.Filename), clientIP(r))
	writeJSON(w, http.StatusCreated, rec)
}

// runBackup 执行一次备份:打包/转储到本地备份目录,记录,按需上传远端。
func (m *Module) runBackup(jobID *int64, kind, target string, remoteID *int64) (Record, error) {
	s, err := m.bs.settings()
	if err != nil {
		return Record{}, err
	}
	if err := os.MkdirAll(s.BackupDir, 0o755); err != nil {
		return Record{}, err
	}
	// 纳秒时间戳:秒级会在同秒多次备份时撞名导致文件互相覆盖。
	now := time.Now()
	ts := fmt.Sprintf("%s-%09d", now.Format("20060102-150405"), now.Nanosecond())
	ext := "tar.gz"
	if kind != "path" {
		ext = "sql"
	}
	filename := fmt.Sprintf("%s-%s-%s.%s", kind, sanitize(target), ts, ext)
	dest, err := system.SafeJoin(s.BackupDir, filename)
	if err != nil {
		return Record{}, err
	}

	var size int64
	switch kind {
	case "path":
		// target 是绝对路径:取其父目录为 root、basename 为 rel,SafeJoin 在 archive 内再校验。
		root := filepath.Dir(target)
		rel := filepath.Base(target)
		size, err = m.arc.archive(root, rel, dest)
	default:
		size, err = m.dmp.dump(kind, target, dest, s)
	}
	if err != nil {
		_ = os.Remove(dest)
		return Record{}, err
	}

	location := "local"
	var recRemoteID *int64
	if remoteID != nil {
		rem, rerr := m.bs.getRemote(*remoteID)
		if rerr != nil {
			return Record{}, fmt.Errorf("unknown remote")
		}
		if uerr := m.rc.upload(dest, rem); uerr != nil {
			return Record{}, fmt.Errorf("upload failed: %w", uerr)
		}
		location, recRemoteID = "remote", remoteID
	}

	return m.bs.addRecord(Record{
		JobID:      jobID,
		TargetKind: kind,
		Target:     target,
		Filename:   filename,
		Location:   location,
		RemoteID:   recRemoteID,
		Size:       size,
	})
}

func (m *Module) handleRestore(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rec, err := m.bs.getRecord(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// 仅支持目录类备份的还原(数据库还原走 mysql/psql,留待数据库模块,避免越权执行)。
	if rec.TargetKind != "path" {
		http.Error(w, "restore supported only for path backups", http.StatusBadRequest)
		return
	}

	var restoreDest struct {
		Dest string `json:"dest"` // 还原目标根目录(必填,显式指定避免误覆盖原路径)
	}
	if derr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&restoreDest); derr != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if restoreDest.Dest == "" {
		http.Error(w, "dest required", http.StatusBadRequest)
		return
	}

	s, _ := m.bs.settings()
	local, perr := system.SafeJoin(s.BackupDir, rec.Filename)
	if perr != nil {
		http.Error(w, "invalid backup path", http.StatusInternalServerError)
		return
	}
	// 远端备份先取回本地再解。
	if rec.Location == "remote" {
		if rec.RemoteID == nil {
			http.Error(w, "record missing remote", http.StatusConflict)
			return
		}
		rem, rerr := m.bs.getRemote(*rec.RemoteID)
		if rerr != nil {
			http.Error(w, "unknown remote", http.StatusConflict)
			return
		}
		if derr := m.rc.download(rec.Filename, local, rem); derr != nil {
			log.Printf("backup: download for restore failed: %v", derr)
			http.Error(w, "fetch from remote failed", http.StatusBadGateway)
			return
		}
	}
	if err := m.arc.extract(local, restoreDest.Dest); err != nil {
		log.Printf("backup: restore extract failed: %v", err)
		http.Error(w, "restore failed: "+safeErr(err), http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "backup.restore", fmt.Sprintf("%s -> %s", rec.Filename, restoreDest.Dest), clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleDeleteRecord(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rec, err := m.bs.getRecord(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if rec.Location == "local" {
		s, _ := m.bs.settings()
		if path, perr := system.SafeJoin(s.BackupDir, rec.Filename); perr == nil {
			_ = os.Remove(path)
		}
	}
	if err := m.bs.deleteRecord(id); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "backup.record.delete", rec.Filename, clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- helpers ---

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// sanitize 把 target 压成文件名安全片段(仅字母数字与 -_),其余替换为 _。
func sanitize(s string) string {
	b := make([]rune, 0, len(s))
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
			b = append(b, c)
		default:
			b = append(b, '_')
		}
	}
	if len(b) == 0 {
		return "backup"
	}
	return string(b)
}

// safeErr 返回不泄露内部细节的错误摘要(凭证/路径不进响应体)。
func safeErr(err error) string {
	if errors.Is(err, errUnsafeEntry) {
		return "unsafe archive entry"
	}
	if errors.Is(err, system.ErrPathEscape) {
		return "path not allowed"
	}
	return "operation failed"
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
