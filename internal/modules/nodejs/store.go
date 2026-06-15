package nodejs

import (
	"database/sql"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// nodeStore 是本模块私有 DB 辅助:自建表存项目元数据与模块设置。
// 不动中央 migrations,建表幂等。
type nodeStore struct{ db *sql.DB }

// Project 是一个 Node 项目的元数据。真实运行态由进程管理器查询,不存这里。
type Project struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Directory   string `json:"directory"`    // 已校验的绝对项目目录(基目录内)
	Command     string `json:"command"`      // 启动命令/脚本
	Port        int    `json:"port"`         // 注入 PORT 环境变量
	NodeVersion string `json:"node_version"` // 版本标签或 system/空
	CreatedBy   *int64 `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

const createProjectsTable = `CREATE TABLE IF NOT EXISTS nodejs_projects (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL UNIQUE,
	directory    TEXT NOT NULL,
	command      TEXT NOT NULL,
	port         INTEGER NOT NULL,
	node_version TEXT NOT NULL DEFAULT '',
	created_by   INTEGER,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS nodejs_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

const (
	settingBaseDir = "base_dir"
	settingNodeDir = "node_dir"
	settingConfDir = "conf_dir"
	settingLogDir  = "log_dir"
)

// newNodeStore 建表(幂等)并返回辅助。
func newNodeStore(st *store.Store) (*nodeStore, error) {
	if _, err := st.DB.Exec(createProjectsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &nodeStore{db: st.DB}, nil
}

func (s *nodeStore) list() ([]Project, error) {
	rows, err := s.db.Query(`SELECT id, name, directory, command, port, node_version,
		created_by, created_at, updated_at FROM nodejs_projects ORDER BY name`)
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

func (s *nodeStore) get(id int64) (Project, error) {
	row := s.db.QueryRow(`SELECT id, name, directory, command, port, node_version,
		created_by, created_at, updated_at FROM nodejs_projects WHERE id = ?`, id)
	return scanProject(row)
}

func (s *nodeStore) create(p Project) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO nodejs_projects
		(name, directory, command, port, node_version, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Directory, p.Command, p.Port, p.NodeVersion, p.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *nodeStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM nodejs_projects WHERE id = ?`, id)
	return err
}

// loadSettings 读设置,缺失的 key 回退默认值。
func (s *nodeStore) loadSettings() (Settings, error) {
	out := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM nodejs_settings`)
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
		case settingBaseDir:
			out.BaseDir = v
		case settingNodeDir:
			out.NodeDir = v
		case settingConfDir:
			out.ConfDir = v
		case settingLogDir:
			out.LogDir = v
		}
	}
	return out, rows.Err()
}

// saveSettings upsert 全部设置 key。
func (s *nodeStore) saveSettings(set Settings) error {
	const q = `INSERT INTO nodejs_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	for _, kv := range [][2]string{
		{settingBaseDir, set.BaseDir},
		{settingNodeDir, set.NodeDir},
		{settingConfDir, set.ConfDir},
		{settingLogDir, set.LogDir},
	} {
		if _, err := s.db.Exec(q, kv[0], kv[1]); err != nil {
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
	err := sc.Scan(&p.ID, &p.Name, &p.Directory, &p.Command, &p.Port, &p.NodeVersion,
		&createdBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Project{}, err
	}
	if createdBy.Valid {
		p.CreatedBy = &createdBy.Int64
	}
	return p, nil
}
