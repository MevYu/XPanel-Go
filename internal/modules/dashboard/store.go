package dashboard

import (
	"database/sql"
	"encoding/json"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// dashStore 是本模块私有 DB 辅助:自建 KV 表,不动中央 migrations,建表幂等。
type dashStore struct{ db *sql.DB }

const createKVTable = `CREATE TABLE IF NOT EXISTS dashboard_kv (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

// keyHomeApps 是「首页软件配置」的 KV 键,value 存有序 module id 列表的 JSON 数组。
const keyHomeApps = "home_apps"

// newDashStore 建表(幂等)并返回辅助。
func newDashStore(st *store.Store) (*dashStore, error) {
	if _, err := st.DB.Exec(createKVTable); err != nil {
		return nil, err
	}
	return &dashStore{db: st.DB}, nil
}

// getHomeApps 读首页软件配置;无记录返回空列表。
func (s *dashStore) getHomeApps() ([]string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM dashboard_kv WHERE key = ?`, keyHomeApps).Scan(&v)
	if err == sql.ErrNoRows {
		return []string{}, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return nil, err
	}
	if out == nil {
		out = []string{}
	}
	return out, nil
}

// setHomeApps upsert 首页软件配置(整个有序列表覆盖保存)。
func (s *dashStore) setHomeApps(mods []string) error {
	raw, err := json.Marshal(mods)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO dashboard_kv (key, value) VALUES (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		keyHomeApps, string(raw),
	)
	return err
}
