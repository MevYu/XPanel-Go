package php

import (
	"database/sql"
	"encoding/json"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// phpStore 是本模块私有的 DB 辅助:自建表,不动中央 migrations,建表幂等。
// 只存单例 Settings(JSON),版本/扩展从文件系统实时检测,不入库。
type phpStore struct{ db *sql.DB }

const createKVTable = `CREATE TABLE IF NOT EXISTS php_kv (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
)`

const kvSettings = "settings"

// newPHPStore 建表(幂等)并返回辅助。
func newPHPStore(st *store.Store) (*phpStore, error) {
	if _, err := st.DB.Exec(createKVTable); err != nil {
		return nil, err
	}
	return &phpStore{db: st.DB}, nil
}

// getSettings 读单例设置;无记录时返回出厂默认。
func (s *phpStore) getSettings() (Settings, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM php_kv WHERE k = ?`, kvSettings).Scan(&v)
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
func (s *phpStore) setSettings(set Settings) error {
	v, err := json.Marshal(set)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO php_kv (k, v) VALUES (?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		kvSettings, string(v),
	)
	return err
}
