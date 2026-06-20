package supervisor

import (
	"database/sql"
	"strings"
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
	User        string `json:"user"`
	Priority    int    `json:"priority"`
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
	user         TEXT NOT NULL DEFAULT '',
	priority     INTEGER NOT NULL DEFAULT 999,
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
	// 旧库迁移:为已存在的表补列。新库由 createProgramsTable 已含这两列,
	// ALTER 会报 "duplicate column name",视为已迁移、忽略。
	for _, alter := range []string{
		`ALTER TABLE supervisor_programs ADD COLUMN user TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE supervisor_programs ADD COLUMN priority INTEGER NOT NULL DEFAULT 999`,
	} {
		if _, err := st.DB.Exec(alter); err != nil && !isDuplicateColumn(err) {
			return nil, err
		}
	}
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &supStore{db: st.DB}, nil
}

// isDuplicateColumn 判断 ADD COLUMN 是否因列已存在而失败(SQLite 报 "duplicate column name")。
func isDuplicateColumn(err error) bool {
	return strings.Contains(err.Error(), "duplicate column")
}

func (s *supStore) list() ([]Program, error) {
	rows, err := s.db.Query(`SELECT id, name, command, directory, auto_restart, numprocs,
		user, priority, created_by, created_at, updated_at FROM supervisor_programs ORDER BY name`)
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
		user, priority, created_by, created_at, updated_at FROM supervisor_programs WHERE id = ?`, id)
	return scanProgram(row)
}

func (s *supStore) create(p Program) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO supervisor_programs
		(name, command, directory, auto_restart, numprocs, user, priority, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.Name, p.Command, p.Directory, boolToInt(p.AutoRestart), p.Numprocs, p.User, p.Priority, p.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// update 改写一条程序的可编辑字段(名称/命令/目录/自启/进程数),并刷新 updated_at。
// 名称唯一约束冲突时返回错误。
func (s *supStore) update(p Program) error {
	_, err := s.db.Exec(`UPDATE supervisor_programs
		SET name = ?, command = ?, directory = ?, auto_restart = ?, numprocs = ?, user = ?, priority = ?, updated_at = ?
		WHERE id = ?`,
		p.Name, p.Command, p.Directory, boolToInt(p.AutoRestart), p.Numprocs, p.User, p.Priority, time.Now().Unix(), p.ID)
	return err
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
		&p.User, &p.Priority, &createdBy, &p.CreatedAt, &p.UpdatedAt)
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
