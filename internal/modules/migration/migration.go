// Package migration 实现一键迁移模块:把指定站点目录 + 关联数据库 + 元信息打成单个迁移包
// (tar.gz),以及从迁移包还原站点文件 + 导入数据库。对标 aaPanel 一键迁移。
//
// 安全:迁移包暂存目录可配置(默认 /www/migration),包内成员路径经 SafeJoin 限定(tar slip 防护);
// 数据库走 mysqldump/pg_dump/mysql/psql CLI 参数数组(绝不拼 shell);导出/导入均需 admin,
// 导入(覆盖)额外需 X-Confirm-Danger + 审计。绝不执行迁移包内任何文件。
package migration

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
	"sync"
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
	ClientIP  func(*http.Request) string                      // 取真实客户端 IP(受信代理感知)
}

// Module 是可开关的一键迁移模块。
type Module struct {
	ms   *migrationStore
	deps Deps

	pk  packer
	dmp dumper
	rst restorer

	// 异步任务生命周期。状态跨 goroutine 经 store(DB)同步,这里只管取消信号与等待。
	wg     sync.WaitGroup
	mu     sync.Mutex // 仅保护 cancel(Start/Stop 可被 Manager 串行调用)
	cancel context.CancelFunc
}

// New 建表并返回模块。建表失败直接 panic:模块无法工作。
// 在 New 里就备好 cancel,使未经 Start 的调用方(测试)Stop 时也能解除等待。
func New(st *store.Store, deps Deps) *Module {
	ms, err := newMigrationStore(st)
	if err != nil {
		panic("migration: init store: " + err.Error())
	}
	m := &Module{
		ms:   ms,
		deps: deps,
		pk:   tarPacker{},
		dmp:  cmdDumper{},
		rst:  cmdRestorer{},
	}
	_, m.cancel = context.WithCancel(context.Background())
	return m
}

func (*Module) Meta() module.ModuleMeta {
	return module.ModuleMeta{ID: "migration", Name: "一键迁移", Category: "系统"}
}

func (*Module) Nav() []module.NavItem {
	return []module.NavItem{{Label: "一键迁移", Icon: "truck", Path: "/migration"}}
}

// Start 由 Manager 在模块启用时调用,必须快速返回。cancel 仅用于 Stop 时发出停机信号。
func (m *Module) Start(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, m.cancel = context.WithCancel(ctx)
	return nil
}

// Stop 触发取消并等待在飞任务 goroutine 收尾(不泄漏)。任务体本身未做中途取消感知,
// 这里等待当前任务体跑完即可。
func (m *Module) Stop(context.Context) error {
	m.mu.Lock()
	if m.cancel != nil {
		m.cancel()
	}
	m.mu.Unlock()
	m.wg.Wait()
	return nil
}

// HealthCheck:打包用 stdlib(archive/tar+gzip),mysqldump/mysql 缺失只影响带库迁移,
// 运行时报错,不阻止启用。
func (*Module) HealthCheck() error { return nil }

func (m *Module) Routes(r module.Router) {
	r.Get("/settings", m.handleGetSettings) // admin 只读
	r.Put("/settings", m.handlePutSettings) // admin 写

	r.Get("/packages", m.handleListPackages)           // admin:迁移包列表
	r.Get("/packages/{id}/download", m.handleDownload) // admin:下载迁移包
	r.Delete("/packages/{id}", m.handleDeletePackage)  // admin:删除迁移包
	r.Get("/packages/{id}/manifest", m.handleManifest) // admin:预览包内元信息

	r.Post("/export", m.handleExport) // admin:导出(打包站点+库+元信息),异步,返回 task_id
	r.Post("/import", m.handleImport) // 危险:admin + X-Confirm-Danger(覆盖站点/库),异步

	r.Get("/tasks", m.handleListTasks)    // admin:任务列表(新到旧)
	r.Get("/tasks/{id}", m.handleGetTask) // admin:单任务进度/状态
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
	s, err := m.ms.settings()
	if err != nil {
		log.Printf("migration: settings load failed: %v", err)
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
	if err := m.ms.saveSettings(in); err != nil {
		log.Printf("migration: settings save failed: %v", err)
		http.Error(w, "settings save failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "migration.settings.update", "", m.clientIP(r))
	s, _ := m.ms.settings()
	writeJSON(w, http.StatusOK, s)
}

// --- packages ---

func (m *Module) handleListPackages(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	list, err := m.ms.listPackages()
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) handleManifest(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	pkg, err := m.ms.getPackage(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	path, perr := m.packagePath(pkg.Filename)
	if perr != nil {
		http.Error(w, "invalid package path", http.StatusInternalServerError)
		return
	}
	meta, err := m.pk.readManifest(path)
	if err != nil {
		log.Printf("migration: read manifest failed: %v", err)
		http.Error(w, "manifest unavailable", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, meta)
}

func (m *Module) handleDownload(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	pkg, err := m.ms.getPackage(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	path, perr := m.packagePath(pkg.Filename)
	if perr != nil {
		http.Error(w, "invalid package path", http.StatusInternalServerError)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	m.deps.Audit(&uid, "migration.download", pkg.Filename, m.clientIP(r))
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+pkg.Filename+"\"")
	http.ServeContent(w, r, pkg.Filename, time.Unix(pkg.CreatedAt, 0), f)
}

func (m *Module) handleDeletePackage(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	pkg, err := m.ms.getPackage(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if path, perr := m.packagePath(pkg.Filename); perr == nil {
		_ = os.Remove(path)
	}
	if err := m.ms.deletePackage(id); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "migration.package.delete", pkg.Filename, m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// --- export ---

// exportRequest 是 POST /export 的请求体。
type exportRequest struct {
	Name       string `json:"name"`        // 迁移包逻辑名(空则用域名/时间戳)
	SitePath   string `json:"site_path"`   // 站点目录绝对路径(必填)
	Domain     string `json:"domain"`      // 站点域名(元信息)
	PHPVersion string `json:"php_version"` // PHP 版本(元信息)
	DBKind     string `json:"db_kind"`     // "" | "mysql" | "postgres"
	DBName     string `json:"db_name"`     // db_kind 非空时必填
}

func (m *Module) handleExport(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	var in exportRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if in.SitePath == "" || !filepath.IsAbs(in.SitePath) {
		http.Error(w, "site_path must be an absolute path", http.StatusBadRequest)
		return
	}
	if !validDBKind(in.DBKind) {
		http.Error(w, "invalid db_kind", http.StatusBadRequest)
		return
	}
	if in.DBKind != "" && !validDBName(in.DBName) {
		http.Error(w, "db_name required and must be valid when db_kind set", http.StatusBadRequest)
		return
	}
	if fi, err := os.Stat(in.SitePath); err != nil || !fi.IsDir() {
		http.Error(w, "site_path is not an existing directory", http.StatusBadRequest)
		return
	}

	task, err := m.ms.createTask("export")
	if err != nil {
		http.Error(w, "task create failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "migration.export", in.SitePath, m.clientIP(r))

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		_ = m.ms.updateTaskRunning(task.ID)
		_ = m.ms.updateTaskProgress(task.ID, 50, "packing")
		pkg, err := m.runExport(in)
		if err != nil {
			log.Printf("migration: export task %d failed: %v", task.ID, err)
			_ = m.ms.finishTask(task.ID, "failed", safeErr(err))
			return
		}
		_ = m.ms.finishTask(task.ID, "success", pkg.Filename)
	}()

	writeJSON(w, http.StatusAccepted, map[string]int64{"task_id": task.ID})
}

// runExport 打包站点目录(+ 可选数据库转储)+ 元信息到迁移暂存目录,落库记录。
func (m *Module) runExport(in exportRequest) (Package, error) {
	s, err := m.ms.settings()
	if err != nil {
		return Package{}, err
	}
	if err := os.MkdirAll(s.MigrationDir, 0o755); err != nil {
		return Package{}, err
	}
	now := time.Now()
	name := in.Name
	if name == "" {
		name = in.Domain
	}
	if name == "" {
		name = "site"
	}
	ts := fmt.Sprintf("%s-%09d", now.Format("20060102-150405"), now.Nanosecond())
	filename := fmt.Sprintf("%s-%s.tar.gz", sanitize(name), ts)
	dest, err := system.SafeJoin(s.MigrationDir, filename)
	if err != nil {
		return Package{}, err
	}

	// 数据库转储到迁移目录内的临时文件,打包后删除——绝不留在包外。
	dbDump := ""
	if in.DBKind != "" {
		dbDump, err = system.SafeJoin(s.MigrationDir, filename+".db.tmp")
		if err != nil {
			return Package{}, err
		}
		if _, err := m.dmp.dump(in.DBKind, in.DBName, dbDump, s); err != nil {
			_ = os.Remove(dbDump)
			return Package{}, err
		}
		defer os.Remove(dbDump)
	}

	meta := Meta{
		Name:       name,
		Domain:     in.Domain,
		SitePath:   in.SitePath,
		PHPVersion: in.PHPVersion,
		DBKind:     in.DBKind,
		DBName:     in.DBName,
		CreatedAt:  now.Unix(),
	}
	size, err := m.pk.pack(in.SitePath, dbDump, meta, dest)
	if err != nil {
		_ = os.Remove(dest)
		return Package{}, err
	}

	return m.ms.addPackage(Package{
		Name:       name,
		Filename:   filename,
		Domain:     in.Domain,
		SitePath:   in.SitePath,
		PHPVersion: in.PHPVersion,
		DBKind:     in.DBKind,
		DBName:     in.DBName,
		Size:       size,
	})
}

// --- import (危险) ---

// importRequest 是 POST /import 的请求体。
type importRequest struct {
	PackageID int64  `json:"package_id"` // 要导入的迁移包记录 ID(必填)
	SiteDest  string `json:"site_dest"`  // 站点还原目标根目录绝对路径(必填,显式指定避免误覆盖)
	ImportDB  bool   `json:"import_db"`  // 是否导入包内数据库(覆盖目标库,危险)
	DBName    string `json:"db_name"`    // 覆盖 manifest 中的目标库名(空则用 manifest)
}

func (m *Module) handleImport(w http.ResponseWriter, r *http.Request) {
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	var in importRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if in.SiteDest == "" || !filepath.IsAbs(in.SiteDest) {
		http.Error(w, "site_dest must be an absolute path", http.StatusBadRequest)
		return
	}
	pkg, err := m.ms.getPackage(in.PackageID)
	if err != nil {
		http.Error(w, "unknown package_id", http.StatusBadRequest)
		return
	}

	task, err := m.ms.createTask("import")
	if err != nil {
		http.Error(w, "task create failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "migration.import", fmt.Sprintf("%s -> %s (db=%t)", pkg.Filename, in.SiteDest, in.ImportDB), m.clientIP(r))

	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		_ = m.ms.updateTaskRunning(task.ID)
		_ = m.ms.updateTaskProgress(task.ID, 50, "restoring")
		if err := m.runImport(pkg, in); err != nil {
			log.Printf("migration: import task %d failed: %v", task.ID, err)
			_ = m.ms.finishTask(task.ID, "failed", safeErr(err))
			return
		}
		_ = m.ms.finishTask(task.ID, "success", pkg.Filename)
	}()

	writeJSON(w, http.StatusAccepted, map[string]int64{"task_id": task.ID})
}

// --- tasks ---

func (m *Module) handleListTasks(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	list, err := m.ms.listTasks()
	if err != nil {
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (m *Module) handleGetTask(w http.ResponseWriter, r *http.Request) {
	if _, ok := m.requireAdmin(w, r); !ok {
		return
	}
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	task, err := m.ms.getTask(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, http.StatusOK, task)
}

// runImport 解包站点文件到 site_dest,可选把包内数据库转储导入目标库。绝不执行包内任何文件。
func (m *Module) runImport(pkg Package, in importRequest) error {
	s, err := m.ms.settings()
	if err != nil {
		return err
	}
	src, err := m.packagePath(pkg.Filename)
	if err != nil {
		return err
	}
	meta, err := m.pk.readManifest(src)
	if err != nil {
		return err
	}

	// 数据库转储解到迁移目录内临时文件,导入后删除(不落到站点目录,避免被当作站点文件)。
	dbDumpDest := ""
	if in.ImportDB && meta.DBKind != "" {
		dbDumpDest, err = system.SafeJoin(s.MigrationDir, pkg.Filename+".restore.tmp")
		if err != nil {
			return err
		}
		defer os.Remove(dbDumpDest)
	}

	hasDB, err := m.pk.unpack(src, in.SiteDest, dbDumpDest)
	if err != nil {
		return err
	}

	if in.ImportDB {
		if meta.DBKind == "" || !hasDB {
			return fmt.Errorf("package contains no database to import")
		}
		dbName := in.DBName
		if dbName == "" {
			dbName = meta.DBName
		}
		if !validDBName(dbName) {
			return fmt.Errorf("invalid target database name")
		}
		if err := m.rst.restore(meta.DBKind, dbName, dbDumpDest, s); err != nil {
			return err
		}
	}
	return nil
}

// --- helpers ---

// packagePath 把迁移包文件名限定在暂存目录内,返回绝对路径(防穿越)。
func (m *Module) packagePath(filename string) (string, error) {
	s, err := m.ms.settings()
	if err != nil {
		return "", err
	}
	return system.SafeJoin(s.MigrationDir, filename)
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}

// sanitize 把字符串压成文件名安全片段(仅字母数字与 -_),其余替换为 _。
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
		return "site"
	}
	return string(b)
}

// safeErr 返回不泄露内部细节的错误摘要(凭证/路径不进响应体)。
func safeErr(err error) string {
	switch {
	case errors.Is(err, errUnsafeEntry):
		return "unsafe archive entry"
	case errors.Is(err, system.ErrPathEscape):
		return "path not allowed"
	case errors.Is(err, errNoManifest):
		return "not a valid migration package"
	case errors.Is(err, errUnpackTooLarge):
		return "migration package too large"
	}
	return "operation failed"
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
