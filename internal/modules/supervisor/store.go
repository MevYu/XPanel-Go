package supervisor

import (
	"database/sql"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// supStore 是本模块私有的 DB 辅助:自建表,管理守护程序元数据与模块设置。
// 不动中央 migrations,建表幂等。
type supStore struct{ db *sql.DB }

// Program 是一个守护程序的元数据。真实运行态由 supervisorctl 查询,不存这里。
type Program struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Command     string `json:"command"`
	Directory   string `json:"directory"`
	AutoRestart bool   `json:"auto_restart"`
	Numprocs    int    `json:"numprocs"`
	CreatedBy   *int64 `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

const createProgramsTable = `CREATE TABLE IF NOT EXISTS supervisor_programs (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL UNIQUE,
	command      TEXT NOT NULL,
	directory    TEXT NOT NULL,
	auto_restart INTEGER NOT NULL DEFAULT 1,
	numprocs     INTEGER NOT NULL DEFAULT 1,
	created_by   INTEGER,
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS supervisor_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

const (
	settingConfDir = "conf_dir"
	settingLogDir  = "log_dir"
)

// newSupStore 建表(幂等)并返回辅助。
func newSupStore(st *store.Store) (*supStore, error) {
	if _, err := st.DB.Exec(createProgramsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &supStore{db: st.DB}, nil
}

func (s *supStore) list() ([]Program, error) {
	rows, err := s.db.Query(`SELECT id, name, command, directory, auto_restart, numprocs,
		created_by, created_at, updated_at FROM supervisor_programs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ps []Program
	for rows.Next() {
		p, err := scanProgram(rows)
		if err != nil {
			return nil, err
		}
		ps = append(ps, p)
	}
	return ps, rows.Err()
}

func (s *supStore) get(id int64) (Program, error) {
	row := s.db.QueryRow(`SELECT id, name, command, directory, auto_restart, numprocs,
		created_by, created_at, updated_at FROM supervisor_programs WHERE id = ?`, id)
	return scanProgram(row)
}

func (s *supStore) create(p Program) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO supervisor_programs
		(name, command, directory, auto_restart, numprocs, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Command, p.Directory, boolToInt(p.AutoRestart), p.Numprocs, p.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *supStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM supervisor_programs WHERE id = ?`, id)
	return err
}

// loadSettings 读设置,缺失的 key 回退到默认值。
func (s *supStore) loadSettings() (Settings, error) {
	out := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM supervisor_settings`)
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
		case settingConfDir:
			out.ConfDir = v
		case settingLogDir:
			out.LogDir = v
		}
	}
	return out, rows.Err()
}

// saveSettings upsert 两个设置 key。
func (s *supStore) saveSettings(set Settings) error {
	const q = `INSERT INTO supervisor_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	if _, err := s.db.Exec(q, settingConfDir, set.ConfDir); err != nil {
		return err
	}
	_, err := s.db.Exec(q, settingLogDir, set.LogDir)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanProgram(sc scanner) (Program, error) {
	var p Program
	var autoRestart int
	var createdBy sql.NullInt64
	err := sc.Scan(&p.ID, &p.Name, &p.Command, &p.Directory, &autoRestart, &p.Numprocs,
		&createdBy, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return Program{}, err
	}
	p.AutoRestart = autoRestart != 0
	if createdBy.Valid {
		p.CreatedBy = &createdBy.Int64
	}
	return p, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
