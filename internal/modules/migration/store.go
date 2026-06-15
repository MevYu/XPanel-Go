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

// migrationStore 读写两张表。
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
	if got.MysqlDump != "" {
		cur.MysqlDump = got.MysqlDump
	}
	if got.PgDump != "" {
		cur.PgDump = got.PgDump
	}
	if got.MysqlCLI != "" {
		cur.MysqlCLI = got.MysqlCLI
	}
	if got.PsqlCLI != "" {
		cur.PsqlCLI = got.PsqlCLI
	}
	return cur, nil
}

func (s *migrationStore) saveSettings(in Settings) error {
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
