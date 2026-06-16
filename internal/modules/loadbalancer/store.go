package loadbalancer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// lbStore 是本模块私有 DB 辅助:自建表存均衡组元数据与设置,不动中央 migrations。
type lbStore struct{ db *sql.DB }

// LBGroup 是一条均衡组元数据。Backends 存为 JSON。Config 为已渲染配置文本(便于回显)。
type LBGroup struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Algo       string    `json:"algo"`
	Listen     int       `json:"listen"`
	ServerName string    `json:"server_name"`
	Backends   []Backend `json:"backends"`
	Enabled    bool      `json:"enabled"`
	Config     string    `json:"config"`
	CreatedBy  *int64    `json:"created_by"`
	CreatedAt  int64     `json:"created_at"`
	UpdatedAt  int64     `json:"updated_at"`
}

const createGroupsTable = `CREATE TABLE IF NOT EXISTS lb_groups (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	algo        TEXT NOT NULL,
	listen      INTEGER NOT NULL DEFAULT 80,
	server_name TEXT NOT NULL,
	backends    TEXT NOT NULL,
	enabled     INTEGER NOT NULL DEFAULT 1,
	config      TEXT NOT NULL DEFAULT '',
	created_by  INTEGER,
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
)`

const createLBSettingsTable = `CREATE TABLE IF NOT EXISTS lb_settings (
	id       INTEGER PRIMARY KEY CHECK (id = 1),
	conf_dir TEXT NOT NULL
)`

func newLBStore(st *store.Store) (*lbStore, error) {
	if _, err := st.DB.Exec(createGroupsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createLBSettingsTable); err != nil {
		return nil, err
	}
	return &lbStore{db: st.DB}, nil
}

// getSettings 返回持久化设置;无行则返回默认值(不写库,待用户首次 PUT)。
func (s *lbStore) getSettings() (Settings, error) {
	row := s.db.QueryRow(`SELECT conf_dir FROM lb_settings WHERE id = 1`)
	var set Settings
	err := row.Scan(&set.ConfDir)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return set, nil
}

func (s *lbStore) putSettings(set Settings) error {
	_, err := s.db.Exec(`INSERT INTO lb_settings (id, conf_dir) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET conf_dir=excluded.conf_dir`, set.ConfDir)
	return err
}

func (s *lbStore) list() ([]LBGroup, error) {
	rows, err := s.db.Query(`SELECT id, name, algo, listen, server_name, backends, enabled,
		config, created_by, created_at, updated_at FROM lb_groups ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LBGroup
	for rows.Next() {
		g, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (s *lbStore) get(id int64) (LBGroup, error) {
	row := s.db.QueryRow(`SELECT id, name, algo, listen, server_name, backends, enabled,
		config, created_by, created_at, updated_at FROM lb_groups WHERE id = ?`, id)
	return scanGroup(row)
}

func (s *lbStore) getByName(name string) (LBGroup, error) {
	row := s.db.QueryRow(`SELECT id, name, algo, listen, server_name, backends, enabled,
		config, created_by, created_at, updated_at FROM lb_groups WHERE name = ?`, name)
	return scanGroup(row)
}

func (s *lbStore) create(g LBGroup) (int64, error) {
	now := time.Now().Unix()
	backendsJSON, err := json.Marshal(g.Backends)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO lb_groups (name, algo, listen, server_name, backends, enabled, config, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		g.Name, g.Algo, g.Listen, g.ServerName, string(backendsJSON), boolToInt(g.Enabled), g.Config, g.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *lbStore) setEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE lb_groups SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), time.Now().Unix(), id)
	return err
}

func (s *lbStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM lb_groups WHERE id = ?`, id)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanGroup(sc scanner) (LBGroup, error) {
	var g LBGroup
	var enabled int
	var backendsJSON string
	var createdBy sql.NullInt64
	err := sc.Scan(&g.ID, &g.Name, &g.Algo, &g.Listen, &g.ServerName, &backendsJSON, &enabled,
		&g.Config, &createdBy, &g.CreatedAt, &g.UpdatedAt)
	if err != nil {
		return LBGroup{}, err
	}
	g.Enabled = enabled != 0
	if createdBy.Valid {
		g.CreatedBy = &createdBy.Int64
	}
	if err := json.Unmarshal([]byte(backendsJSON), &g.Backends); err != nil {
		return LBGroup{}, err
	}
	return g, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
