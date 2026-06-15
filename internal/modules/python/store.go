package python

import (
	"database/sql"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// 默认可配置路径。GET/PUT /settings(admin)可覆盖。
const (
	defaultProjectRoot = "/www/python"            // 项目代码基目录
	defaultVenvRoot    = "/www/python/venv"       // venv 基目录
	defaultInterpreter = "python3"                // 默认解释器版本标识
	defaultConfDir     = "/etc/supervisor/conf.d" // 进程配置目录
	defaultLogDir      = "/var/log/xpanel-python" // 项目日志目录
)

// Settings 是模块可配置项,持久化在自建表里。
type Settings struct {
	ProjectRoot string `json:"project_root"` // 项目根基目录
	VenvRoot    string `json:"venv_root"`    // venv 基目录
	Interpreter string `json:"interpreter"`  // 默认 Python 解释器版本标识
	ConfDir     string `json:"conf_dir"`     // 进程配置目录
	LogDir      string `json:"log_dir"`      // 项目日志目录
}

// DefaultSettings 返回内置默认值。
func DefaultSettings() Settings {
	return Settings{
		ProjectRoot: defaultProjectRoot,
		VenvRoot:    defaultVenvRoot,
		Interpreter: defaultInterpreter,
		ConfDir:     defaultConfDir,
		LogDir:      defaultLogDir,
	}
}

// Project 是一个 Python 项目的元数据。真实运行态由 Runner 查询,不存这里。
type Project struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	ProjectDir  string `json:"project_dir"`
	VenvDir     string `json:"venv_dir"`
	Interpreter string `json:"interpreter"`
	StartKind   string `json:"start_kind"`
	AppTarget   string `json:"app_target"`
	Port        int    `json:"port"`
	Workers     int    `json:"workers"`
	CreatedBy   *int64 `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

// pyStore 是本模块私有的 DB 辅助:自建表,管理项目元数据与模块设置。
// 不动中央 migrations,建表幂等。
type pyStore struct{ db *sql.DB }

const createProjectsTable = `CREATE TABLE IF NOT EXISTS python_projects (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL UNIQUE,
	project_dir  TEXT NOT NULL,
	venv_dir     TEXT NOT NULL,
	interpreter  TEXT NOT NULL,
	start_kind   TEXT NOT NULL,
	app_target   TEXT NOT NULL,
	port         INTEGER NOT NULL DEFAULT 0,
	workers      INTEGER NOT NULL DEFAULT 1,
	created_by   INTEGER,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS python_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

const (
	settingProjectRoot = "project_root"
	settingVenvRoot    = "venv_root"
	settingInterpreter = "interpreter"
	settingConfDir     = "conf_dir"
	settingLogDir      = "log_dir"
)

// newPyStore 建表(幂等)并返回辅助。
func newPyStore(st *store.Store) (*pyStore, error) {
	if _, err := st.DB.Exec(createProjectsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &pyStore{db: st.DB}, nil
}

const projectCols = `id, name, project_dir, venv_dir, interpreter, start_kind,
	app_target, port, workers, created_by, created_at, updated_at`

func (s *pyStore) list() ([]Project, error) {
	rows, err := s.db.Query(`SELECT ` + projectCols + ` FROM python_projects ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ps []Project
	for rows.Next() {
		p, err := scanProject(rows)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, rows.Err()
}

func (s *pyStore) get(id int64) (Project, error) {
	row := s.db.QueryRow(`SELECT `+projectCols+` FROM python_projects WHERE id = ?`, id)
	return scanProject(row)
}

func (s *pyStore) create(p Project) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO python_projects
		(name, project_dir, venv_dir, interpreter, start_kind, app_target, port, workers, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.ProjectDir, p.VenvDir, p.Interpreter, p.StartKind, p.AppTarget,
		p.Port, p.Workers, p.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *pyStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM python_projects WHERE id = ?`, id)
	return err
}

// loadSettings 读设置,缺失的 key 回退到默认值。
func (s *pyStore) loadSettings() (Settings, error) {
	out := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM python_settings`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return out, err
		}
		switch k {
		case settingProjectRoot:
			out.ProjectRoot = v
		case settingVenvRoot:
			out.VenvRoot = v
		case settingInterpreter:
			out.Interpreter = v
		case settingConfDir:
			out.ConfDir = v
		case settingLogDir:
			out.LogDir = v
		}
	}
	return out, rows.Err()
}

// saveSettings upsert 全部设置 key。
func (s *pyStore) saveSettings(set Settings) error {
	const q = `INSERT INTO python_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	pairs := [][2]string{
		{settingProjectRoot, set.ProjectRoot},
		{settingVenvRoot, set.VenvRoot},
		{settingInterpreter, set.Interpreter},
		{settingConfDir, set.ConfDir},
		{settingLogDir, set.LogDir},
	}
	for _, p := range pairs {
		if _, err := s.db.Exec(q, p[0], p[1]); err != nil {
			return err
		}
	}
	return nil
}

type scanner interface {
	Scan(dest ...any) error
}

func scanProject(sc scanner) (Project, error) {
	var p Project
	var createdBy sql.NullInt64
	err := sc.Scan(&p.ID, &p.Name, &p.ProjectDir, &p.VenvDir, &p.Interpreter, &p.StartKind,
		&p.AppTarget, &p.Port, &p.Workers, &createdBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Project{}, err
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.Int64
	}
	return p, nil
}
