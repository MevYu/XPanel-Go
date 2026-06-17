package migration

import (
	"database/sql"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// defaultMigrationDir 是迁移包暂存目录(对标 aaPanel 一键迁移)。可在 settings 覆盖。
const defaultMigrationDir = "/www/migration"

// schema 幂等建表:设置 + 迁移包记录。
const schema = `
CREATE TABLE IF NOT EXISTS migration_settings (
	id            INTEGER PRIMARY KEY CHECK (id = 1),
	migration_dir TEXT NOT NULL DEFAULT '',
	mysqldump     TEXT NOT NULL DEFAULT '',
	pgdump        TEXT NOT NULL DEFAULT '',
	mysql_cli     TEXT NOT NULL DEFAULT '',
	psql_cli      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS migration_packages (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	filename    TEXT NOT NULL,
	domain      TEXT NOT NULL DEFAULT '',
	site_path   TEXT NOT NULL DEFAULT '',
	php_version TEXT NOT NULL DEFAULT '',
	db_kind     TEXT NOT NULL DEFAULT '',
	db_name     TEXT NOT NULL DEFAULT '',
	size        INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_tasks (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	kind        TEXT NOT NULL,
	status      TEXT NOT NULL,
	progress    INTEGER NOT NULL DEFAULT 0,
	message     TEXT NOT NULL DEFAULT '',
	started_at  INTEGER NOT NULL DEFAULT 0,
	finished_at INTEGER NOT NULL DEFAULT 0
);`

// Settings 是本模块可配置项。空值回落默认。
type Settings struct {
	MigrationDir string `json:"migration_dir"` // 迁移包暂存目录,默认 /www/migration
	MysqlDump    string `json:"mysqldump"`     // mysqldump 路径,默认 "mysqldump"
	PgDump       string `json:"pgdump"`        // pg_dump 路径,默认 "pg_dump"
	MysqlCLI     string `json:"mysql_cli"`     // mysql 客户端路径(导入用),默认 "mysql"
	PsqlCLI      string `json:"psql_cli"`      // psql 客户端路径(导入用),默认 "psql"
}

func defaultSettings() Settings {
	return Settings{
		MigrationDir: defaultMigrationDir,
		MysqlDump:    "mysqldump",
		PgDump:       "pg_dump",
		MysqlCLI:     "mysql",
		PsqlCLI:      "psql",
	}
}

// Meta 是迁移包元信息:还原时据此重建站点。随包写入 manifest,也落库便于列表展示。
type Meta struct {
	Name       string `json:"name"`        // 迁移包逻辑名
	Domain     string `json:"domain"`      // 站点域名
	SitePath   string `json:"site_path"`   // 原站点目录绝对路径
	PHPVersion string `json:"php_version"` // PHP 版本(如 "8.2"),无则空
	DBKind     string `json:"db_kind"`     // "mysql" | "postgres" | ""(无库)
	DBName     string `json:"db_name"`     // 数据库名
	CreatedAt  int64  `json:"created_at"`  // 导出时间(Unix 秒)
}

// Package 是一个迁移包的落库记录。
type Package struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Filename   string `json:"filename"`
	Domain     string `json:"domain"`
	SitePath   string `json:"site_path"`
	PHPVersion string `json:"php_version"`
	DBKind     string `json:"db_kind"`
	DBName     string `json:"db_name"`
	Size       int64  `json:"size"`
	CreatedAt  int64  `json:"created_at"`
}

// Task 是一次异步导出/导入任务的进度记录。状态机:pending -> running -> success|failed。
type Task struct {
	ID         int64  `json:"id"`
	Kind       string `json:"kind"`        // "export" | "import"
	Status     string `json:"status"`      // pending | running | success | failed
	Progress   int    `json:"progress"`    // 0-100
	Message    string `json:"message"`     // 成功为产物文件名,失败为脱敏错误摘要
	StartedAt  int64  `json:"started_at"`  // Unix 秒,running 前为 0
	FinishedAt int64  `json:"finished_at"` // Unix 秒,终态前为 0
}

// migrationStore 读写三张表。
type migrationStore struct{ db *sql.DB }

func newMigrationStore(st *store.Store) (*migrationStore, error) {
	if _, err := st.DB.Exec(schema); err != nil {
		return nil, err
	}
	return &migrationStore{db: st.DB}, nil
}

// --- settings ---

func (s *migrationStore) settings() (Settings, error) {
	cur := defaultSettings()
	var got Settings
	row := s.db.QueryRow(`SELECT migration_dir, mysqldump, pgdump, mysql_cli, psql_cli
		FROM migration_settings WHERE id = 1`)
	err := row.Scan(&got.MigrationDir, &got.MysqlDump, &got.PgDump, &got.MysqlCLI, &got.PsqlCLI)
	if errors.Is(err, sql.ErrNoRows) {
		return cur, nil
	}
	if err != nil {
		return Settings{}, err
	}
	if got.MigrationDir != "" {
		cur.MigrationDir = got.MigrationDir
	}
	// 载入时也校验:历史/被篡改的非法工具路径回落内置默认名,绝不当程序执行。
	if got.MysqlDump != "" && validToolPath(got.MysqlDump) {
		cur.MysqlDump = got.MysqlDump
	}
	if got.PgDump != "" && validToolPath(got.PgDump) {
		cur.PgDump = got.PgDump
	}
	if got.MysqlCLI != "" && validToolPath(got.MysqlCLI) {
		cur.MysqlCLI = got.MysqlCLI
	}
	if got.PsqlCLI != "" && validToolPath(got.PsqlCLI) {
		cur.PsqlCLI = got.PsqlCLI
	}
	return cur, nil
}

// errInvalidToolPath 表示某个 DB 工具配置不是简单二进制名,也不是受信目录下存在的绝对路径。
var errInvalidToolPath = errors.New("invalid db tool path")

func (s *migrationStore) saveSettings(in Settings) error {
	if !validToolSettings(in) {
		return errInvalidToolPath
	}
	_, err := s.db.Exec(`INSERT INTO migration_settings
		(id, migration_dir, mysqldump, pgdump, mysql_cli, psql_cli)
		VALUES (1, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 migration_dir=excluded.migration_dir, mysqldump=excluded.mysqldump,
		 pgdump=excluded.pgdump, mysql_cli=excluded.mysql_cli, psql_cli=excluded.psql_cli`,
		in.MigrationDir, in.MysqlDump, in.PgDump, in.MysqlCLI, in.PsqlCLI)
	return err
}

// --- packages ---

func (s *migrationStore) addPackage(p Package) (Package, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO migration_packages
		(name, filename, domain, site_path, php_version, db_kind, db_name, size, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Filename, p.Domain, p.SitePath, p.PHPVersion, p.DBKind, p.DBName, p.Size, now)
	if err != nil {
		return Package{}, err
	}
	id, _ := res.LastInsertId()
	p.ID, p.CreatedAt = id, now
	return p, nil
}

func (s *migrationStore) listPackages() ([]Package, error) {
	rows, err := s.db.Query(`SELECT id, name, filename, domain, site_path, php_version, db_kind, db_name, size, created_at
		FROM migration_packages ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Package{}
	for rows.Next() {
		var p Package
		if err := rows.Scan(&p.ID, &p.Name, &p.Filename, &p.Domain, &p.SitePath,
			&p.PHPVersion, &p.DBKind, &p.DBName, &p.Size, &p.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *migrationStore) getPackage(id int64) (Package, error) {
	var p Package
	row := s.db.QueryRow(`SELECT id, name, filename, domain, site_path, php_version, db_kind, db_name, size, created_at
		FROM migration_packages WHERE id = ?`, id)
	err := row.Scan(&p.ID, &p.Name, &p.Filename, &p.Domain, &p.SitePath,
		&p.PHPVersion, &p.DBKind, &p.DBName, &p.Size, &p.CreatedAt)
	return p, err
}

func (s *migrationStore) deletePackage(id int64) error {
	_, err := s.db.Exec(`DELETE FROM migration_packages WHERE id = ?`, id)
	return err
}

// --- tasks ---

func (s *migrationStore) createTask(kind string) (Task, error) {
	res, err := s.db.Exec(`INSERT INTO migration_tasks (kind, status, progress)
		VALUES (?, 'pending', 0)`, kind)
	if err != nil {
		return Task{}, err
	}
	id, _ := res.LastInsertId()
	return Task{ID: id, Kind: kind, Status: "pending"}, nil
}

func (s *migrationStore) getTask(id int64) (Task, error) {
	var t Task
	row := s.db.QueryRow(`SELECT id, kind, status, progress, message, started_at, finished_at
		FROM migration_tasks WHERE id = ?`, id)
	err := row.Scan(&t.ID, &t.Kind, &t.Status, &t.Progress, &t.Message, &t.StartedAt, &t.FinishedAt)
	return t, err
}

func (s *migrationStore) listTasks() ([]Task, error) {
	rows, err := s.db.Query(`SELECT id, kind, status, progress, message, started_at, finished_at
		FROM migration_tasks ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Task{}
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.ID, &t.Kind, &t.Status, &t.Progress, &t.Message, &t.StartedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *migrationStore) updateTaskRunning(id int64) error {
	_, err := s.db.Exec(`UPDATE migration_tasks SET status = 'running', started_at = ?
		WHERE id = ?`, time.Now().Unix(), id)
	return err
}

func (s *migrationStore) updateTaskProgress(id int64, progress int, message string) error {
	_, err := s.db.Exec(`UPDATE migration_tasks SET progress = ?, message = ? WHERE id = ?`,
		progress, message, id)
	return err
}

// finishTask 落终态:success 进度强制 100,记录 finished_at。
func (s *migrationStore) finishTask(id int64, status, message string) error {
	now := time.Now().Unix()
	if status == "success" {
		_, err := s.db.Exec(`UPDATE migration_tasks SET status = ?, progress = 100,
			message = ?, finished_at = ? WHERE id = ?`, status, message, now, id)
		return err
	}
	_, err := s.db.Exec(`UPDATE migration_tasks SET status = ?, message = ?,
		finished_at = ? WHERE id = ?`, status, message, now, id)
	return err
}
