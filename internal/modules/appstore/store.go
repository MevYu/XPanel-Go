package appstore

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// appStore 是本模块私有 DB 辅助:自建表存已安装实例与设置,不动中央 migrations。
type appStore struct{ db *sql.DB }

// Instance 是一条已安装应用实例的记录。
type Instance struct {
	ID         int64             `json:"id"`
	AppID      string            `json:"app_id"`     // 对应内置目录 App.ID
	Name       string            `json:"name"`       // 实例名(compose 项目名),全局唯一
	Params     map[string]string `json:"params"`     // 安装参数(密码字段在返回时由 handler 决定是否脱敏)
	Compose    string            `json:"compose"`    // 渲染后的 compose 文本
	ProjectDir string            `json:"project_dir"`// compose 项目目录绝对路径
	Status     string            `json:"status"`     // running / stopped
	CreatedBy  *int64            `json:"created_by"`
	CreatedAt  int64             `json:"created_at"`
	UpdatedAt  int64             `json:"updated_at"`
}

const createInstancesTable = `CREATE TABLE IF NOT EXISTS appstore_instances (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	app_id      TEXT NOT NULL,
	name        TEXT NOT NULL UNIQUE,
	params      TEXT NOT NULL,
	compose     TEXT NOT NULL,
	project_dir TEXT NOT NULL,
	status      TEXT NOT NULL DEFAULT 'running',
	created_by  INTEGER,
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
)`

const createAppSettingsTable = `CREATE TABLE IF NOT EXISTS appstore_settings (
	id          INTEGER PRIMARY KEY CHECK (id = 1),
	apps_root   TEXT NOT NULL,
	project_dir TEXT NOT NULL
)`

func newAppStore(st *store.Store) (*appStore, error) {
	if _, err := st.DB.Exec(createInstancesTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createAppSettingsTable); err != nil {
		return nil, err
	}
	return &appStore{db: st.DB}, nil
}

func (s *appStore) getSettings() (Settings, error) {
	row := s.db.QueryRow(`SELECT apps_root, project_dir FROM appstore_settings WHERE id = 1`)
	var set Settings
	err := row.Scan(&set.AppsRoot, &set.ProjectDir)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return set, nil
}

func (s *appStore) putSettings(set Settings) error {
	_, err := s.db.Exec(`INSERT INTO appstore_settings (id, apps_root, project_dir)
		VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET apps_root=excluded.apps_root, project_dir=excluded.project_dir`,
		set.AppsRoot, set.ProjectDir)
	return err
}

func (s *appStore) list() ([]Instance, error) {
	rows, err := s.db.Query(`SELECT id, app_id, name, params, compose, project_dir, status,
		created_by, created_at, updated_at FROM appstore_instances ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Instance
	for rows.Next() {
		inst, err := scanInstance(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, rows.Err()
}

func (s *appStore) get(id int64) (Instance, error) {
	row := s.db.QueryRow(`SELECT id, app_id, name, params, compose, project_dir, status,
		created_by, created_at, updated_at FROM appstore_instances WHERE id = ?`, id)
	return scanInstance(row)
}

func (s *appStore) getByName(name string) (Instance, error) {
	row := s.db.QueryRow(`SELECT id, app_id, name, params, compose, project_dir, status,
		created_by, created_at, updated_at FROM appstore_instances WHERE name = ?`, name)
	return scanInstance(row)
}

func (s *appStore) create(inst Instance) (int64, error) {
	now := time.Now().Unix()
	paramsJSON, err := json.Marshal(inst.Params)
	if err != nil {
		return 0, err
	}
	status := inst.Status
	if status == "" {
		status = "running"
	}
	res, err := s.db.Exec(`INSERT INTO appstore_instances
		(app_id, name, params, compose, project_dir, status, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		inst.AppID, inst.Name, string(paramsJSON), inst.Compose, inst.ProjectDir, status,
		inst.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *appStore) setStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE appstore_instances SET status = ?, updated_at = ? WHERE id = ?`,
		status, time.Now().Unix(), id)
	return err
}

func (s *appStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM appstore_instances WHERE id = ?`, id)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanInstance(sc scanner) (Instance, error) {
	var inst Instance
	var paramsJSON string
	var createdBy sql.NullInt64
	err := sc.Scan(&inst.ID, &inst.AppID, &inst.Name, &paramsJSON, &inst.Compose,
		&inst.ProjectDir, &inst.Status, &createdBy, &inst.CreatedAt, &inst.UpdatedAt)
	if err != nil {
		return Instance{}, err
	}
	if createdBy.Valid {
		inst.CreatedBy = &createdBy.Int64
	}
	if err := json.Unmarshal([]byte(paramsJSON), &inst.Params); err != nil {
		return Instance{}, err
	}
	return inst, nil
}
