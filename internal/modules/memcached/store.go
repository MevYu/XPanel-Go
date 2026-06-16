package memcached

import (
	"database/sql"
	"encoding/json"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mcStore 是本模块私有 DB 辅助:自建表,不动中央 migrations,建表幂等。存单例 Settings(JSON)。
type mcStore struct{ db *sql.DB }

const createKVTable = `CREATE TABLE IF NOT EXISTS memcached_kv (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
)`

const kvSettings = "settings"

// newMCStore 建表(幂等)并返回辅助。
func newMCStore(st *store.Store) (*mcStore, error) {
	if _, err := st.DB.Exec(createKVTable); err != nil {
		return nil, err
	}
	return &mcStore{db: st.DB}, nil
}

// getSettings 读单例设置;无记录时返回出厂默认。
func (s *mcStore) getSettings() (Settings, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM memcached_kv WHERE k = ?`, kvSettings).Scan(&v)
	if err == sql.ErrNoRows {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	var out Settings
	if err := json.Unmarshal([]byte(v), &out); err != nil {
		return Settings{}, err
	}
	return out, nil
}

// setSettings upsert 单例设置(JSON)。
func (s *mcStore) setSettings(set Settings) error {
	v, err := json.Marshal(set)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO memcached_kv (k, v) VALUES (?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		kvSettings, string(v),
	)
	return err
}
