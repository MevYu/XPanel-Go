package database

import (
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
	"github.com/MevYu/XPanel-Go/internal/system"
	"github.com/go-chi/chi/v5"
)

// backupRecord 是一条库级备份记录(API 输出形状)。
type backupRecord struct {
	ID        int64  `json:"id"`
	Engine    string `json:"engine"`
	DBName    string `json:"db_name"`
	Filename  string `json:"filename"`
	Size      int64  `json:"size"`
	CreatedAt string `json:"created_at"`
}

// backupSchema 幂等建表:每条记录对应 backup_dir 内一个 .sql.gz 文件。
const backupSchema = `CREATE TABLE IF NOT EXISTS database_backups (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	engine      TEXT NOT NULL,
	db_name     TEXT NOT NULL,
	filename    TEXT NOT NULL,
	size        INTEGER NOT NULL DEFAULT 0,
	created_at  TEXT NOT NULL
)`

// backupStore 读写 database_backups 表。
type backupStore struct{ db *sql.DB }

func newBackupStore(st *store.Store) (*backupStore, error) {
	if _, err := st.DB.Exec(backupSchema); err != nil {
		return nil, err
	}
	return &backupStore{db: st.DB}, nil
}

func (s *backupStore) insert(engine, dbName, filename string, size int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO database_backups (engine, db_name, filename, size, created_at)
		VALUES (?, ?, ?, ?, ?)`, engine, dbName, filename, size, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *backupStore) list() ([]backupRecord, error) {
	rows, err := s.db.Query(`SELECT id, engine, db_name, filename, size, created_at
		FROM database_backups ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []backupRecord
	for rows.Next() {
		var r backupRecord
		if err := rows.Scan(&r.ID, &r.Engine, &r.DBName, &r.Filename, &r.Size, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *backupStore) get(id int64) (backupRecord, error) {
	var r backupRecord
	err := s.db.QueryRow(`SELECT id, engine, db_name, filename, size, created_at
		FROM database_backups WHERE id = ?`, id).
		Scan(&r.ID, &r.Engine, &r.DBName, &r.Filename, &r.Size, &r.CreatedAt)
	return r, err
}

func (s *backupStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM database_backups WHERE id = ?`, id)
	return err
}

// dumpRestorer 抽象库级转储/恢复,便于在无真实 DB 的环境用 mock 测业务。
// 凭证经 Settings 传入,由实现用环境变量喂给子进程,绝不进 argv。
type dumpRestorer interface {
	dump(ctx context.Context, engine, dbName, destFile string, s Settings) (int64, error)
	restore(ctx context.Context, engine, dbName, srcFile string, s Settings) error
}

// backupEngine 报告 engine 是否支持库级备份(仅 mysql/postgres)。
func backupEngine(engine string) bool { return engine == "mysql" || engine == "postgres" }

// --- HTTP handlers ---

func (m *Module) backupRoutes(r chi.Router) {
	r.Post("/{engine}/databases/{name}/backup", m.handleBackupCreate)
	r.Get("/backups", m.handleBackupList)
	r.Post("/backups/{id}/restore", m.handleBackupRestore) // 危险
	r.Get("/backups/{id}/download", m.handleBackupDownload)
	r.Delete("/backups/{id}", m.handleBackupDelete) // 危险
}

func (m *Module) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	engine := chi.URLParam(r, "engine")
	name := chi.URLParam(r, "name")
	if !backupEngine(engine) {
		http.Error(w, "unsupported engine: must be mysql or postgres", http.StatusBadRequest)
		return
	}
	if !validIdent(name) {
		http.Error(w, errInvalidIdent.Error(), http.StatusBadRequest)
		return
	}
	id, derr := m.backupDatabase(r.Context(), engine, name)
	outcome := "ok"
	if derr != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, engine+".backup", "db="+name+" "+outcome, m.clientIP(r))
	if derr != nil {
		switch {
		case errors.Is(derr, errBackupSettings), errors.Is(derr, errBackupDir):
			http.Error(w, "backup unavailable", http.StatusInternalServerError)
		case errors.Is(derr, errBackupRecord):
			http.Error(w, "backup record failed", http.StatusInternalServerError)
		default:
			log.Printf("database: backup %s %s failed: %v", engine, name, derr)
			http.Error(w, "backup failed", http.StatusBadGateway)
		}
		return
	}
	rec, _ := m.bs.get(id)
	writeJSON(w, http.StatusOK, rec)
}

var (
	errBackupSettings = errors.New("settings unavailable")
	errBackupDir      = errors.New("backup directory unavailable")
	errBackupRecord   = errors.New("backup record failed")
)

// BackupDatabase 转储单库到 BackupDir 并落库记录,返回记录 ID。供 cron 钩子复用。
// 调用方负责 engine/dbName 的合法性(此处仍做白名单兜底,纵深防御)。
func (m *Module) BackupDatabase(engine, dbName string) error {
	if !backupEngine(engine) {
		return fmt.Errorf("unsupported engine %q: must be mysql or postgres", engine)
	}
	if !validIdent(dbName) {
		return errInvalidIdent
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	_, err := m.backupDatabase(ctx, engine, dbName)
	return err
}

// backupDatabase 是备份核心逻辑:转储到 BackupDir,落库记录,返回记录 ID。
func (m *Module) backupDatabase(ctx context.Context, engine, dbName string) (int64, error) {
	eff, err := m.ss.effective()
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errBackupSettings, err)
	}
	if err := os.MkdirAll(eff.BackupDir, 0o700); err != nil {
		return 0, fmt.Errorf("%w: %v", errBackupDir, err)
	}
	filename := backupFilename(engine, dbName)
	dest, err := system.SafeJoin(eff.BackupDir, filename)
	if err != nil {
		return 0, fmt.Errorf("invalid backup path: %w", err)
	}
	size, err := m.dumper.dump(ctx, engine, dbName, dest, eff)
	if err != nil {
		_ = os.Remove(dest)
		return 0, err
	}
	id, err := m.bs.insert(engine, dbName, filename, size)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", errBackupRecord, err)
	}
	return id, nil
}

func (m *Module) handleBackupList(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	recs, err := m.bs.list()
	if err != nil {
		log.Printf("database: backup list failed: %v", err)
		http.Error(w, "backup list failed", http.StatusInternalServerError)
		return
	}
	if recs == nil {
		recs = []backupRecord{}
	}
	writeJSON(w, http.StatusOK, recs)
}

func (m *Module) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	rec, eff, src, ok := m.backupFile(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
	defer cancel()
	err := m.dumper.restore(ctx, rec.Engine, rec.DBName, src, eff)
	outcome := "ok"
	if err != nil {
		outcome = "failed"
	}
	m.deps.Audit(&uid, rec.Engine+".restore", "db="+rec.DBName+" "+outcome, m.clientIP(r))
	if err != nil {
		log.Printf("database: restore %s %s failed: %v", rec.Engine, rec.DBName, err)
		http.Error(w, "restore failed", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (m *Module) handleBackupDownload(w http.ResponseWriter, r *http.Request) {
	if _, role := m.deps.Principal(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	rec, _, src, ok := m.backupFile(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+rec.Filename+"\"")
	http.ServeFile(w, r, src)
}

func (m *Module) handleBackupDelete(w http.ResponseWriter, r *http.Request) {
	uid, role := m.deps.Principal(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	if !confirmed(r) {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	rec, _, src, ok := m.backupFile(w, r)
	if !ok {
		return
	}
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		log.Printf("database: backup file remove failed: %v", err)
		http.Error(w, "backup delete failed", http.StatusInternalServerError)
		return
	}
	if err := m.bs.delete(rec.ID); err != nil {
		log.Printf("database: backup record delete failed: %v", err)
		http.Error(w, "backup delete failed", http.StatusInternalServerError)
		return
	}
	m.deps.Audit(&uid, "database.backup.delete", "id="+strconv.FormatInt(rec.ID, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// backupFile 取记录并把其 filename 经 SafeJoin 限定在 backup_dir 内,返回绝对路径。
// 404(记录不存在)与 400(路径穿越)在此统一处理。
func (m *Module) backupFile(w http.ResponseWriter, r *http.Request) (backupRecord, Settings, string, bool) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		http.Error(w, "invalid backup id", http.StatusBadRequest)
		return backupRecord{}, Settings{}, "", false
	}
	rec, err := m.bs.get(id)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "backup not found", http.StatusNotFound)
		return backupRecord{}, Settings{}, "", false
	}
	if err != nil {
		log.Printf("database: backup get failed: %v", err)
		http.Error(w, "backup lookup failed", http.StatusInternalServerError)
		return backupRecord{}, Settings{}, "", false
	}
	eff, err := m.ss.effective()
	if err != nil {
		http.Error(w, "settings unavailable", http.StatusInternalServerError)
		return backupRecord{}, Settings{}, "", false
	}
	if !safeBackupName(rec.Filename) {
		http.Error(w, "invalid backup path", http.StatusBadRequest)
		return backupRecord{}, Settings{}, "", false
	}
	src, err := system.SafeJoin(eff.BackupDir, rec.Filename)
	if err != nil {
		http.Error(w, "invalid backup path", http.StatusBadRequest)
		return backupRecord{}, Settings{}, "", false
	}
	return rec, eff, src, true
}

// safeBackupName 报告 filename 是否为不含路径分隔/穿越的纯文件名。
// 落库的备份名一律由 backupFilename 生成(纯 basename),任何偏离一律拒绝(纵深防御)。
func safeBackupName(filename string) bool {
	if filename == "" || filename != filepath.Base(filename) {
		return false
	}
	return !strings.Contains(filename, "/") && filename != ".." && filename != "."
}

// backupFilename 构造 backup_dir 内的相对文件名。engine/dbName 已校验,只含安全字符。
func backupFilename(engine, dbName string) string {
	return fmt.Sprintf("%s-%s-%s.sql.gz", engine, dbName, time.Now().UTC().Format("20060102-150405"))
}

// --- 真实转储/恢复:mysqldump/pg_dump + mysql/psql,参数数组,凭证走环境变量 ---

type cmdDumpRestorer struct{}

// dump 用 mysqldump/pg_dump 把单库导出,经 gzip 压缩写到 destFile。
// 凭证经环境变量(MYSQL_PWD/PGPASSWORD)传给子进程,绝不进 argv。
func (cmdDumpRestorer) dump(ctx context.Context, engine, dbName, destFile string, s Settings) (int64, error) {
	name, args, env := dumpCmd(engine, dbName, s)
	out, err := os.Create(destFile)
	if err != nil {
		return 0, err
	}
	defer out.Close()
	gz := gzip.NewWriter(out)

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdout = gz
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		gz.Close()
		return 0, fmt.Errorf("%s failed: %w", name, err)
	}
	if err := gz.Close(); err != nil {
		return 0, err
	}
	st, err := out.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// restore 用 mysql/psql 把 .sql.gz 解压回灌到目标库。凭证同样走环境变量。
func (cmdDumpRestorer) restore(ctx context.Context, engine, dbName, srcFile string, s Settings) error {
	name, args, env := restoreCmd(engine, dbName, s)
	f, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	cmd.Stdin = gz
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

// dumpCmd 组装转储命令:argv 只含非敏感连接参数,密码走 env。
func dumpCmd(engine, dbName string, s Settings) (name string, args, env []string) {
	if engine == "postgres" {
		args = pgArgs(s)
		args = append(args, dbName)
		return "pg_dump", args, append(os.Environ(), "PGPASSWORD="+s.PGPassword)
	}
	args = mysqlArgs(s)
	args = append(args, "--single-transaction", "--databases", dbName)
	return "mysqldump", args, append(os.Environ(), "MYSQL_PWD="+s.MySQLPassword)
}

// restoreCmd 组装恢复命令。
func restoreCmd(engine, dbName string, s Settings) (name string, args, env []string) {
	if engine == "postgres" {
		args = pgArgs(s)
		args = append(args, "-d", dbName)
		return "psql", args, append(os.Environ(), "PGPASSWORD="+s.PGPassword)
	}
	args = mysqlArgs(s)
	args = append(args, dbName)
	return "mysql", args, append(os.Environ(), "MYSQL_PWD="+s.MySQLPassword)
}

func mysqlArgs(s Settings) []string {
	if s.MySQLSocket != "" {
		return []string{"--user=" + s.MySQLUser, "--socket=" + s.MySQLSocket}
	}
	return []string{"--user=" + s.MySQLUser, "--host=" + s.MySQLHost, "--port=" + strconv.Itoa(s.MySQLPort)}
}

func pgArgs(s Settings) []string {
	return []string{"--host=" + s.PGHost, "--port=" + strconv.Itoa(s.PGPort), "--username=" + s.PGUser, "--no-password"}
}
