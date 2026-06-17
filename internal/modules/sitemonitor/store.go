package sitemonitor

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// monitorStore 是本模块私有 DB 辅助:自建表,不动中央 migrations,建表幂等。
// 存单例 Settings(JSON)与聚合统计快照(供历史/趋势对比)。
type monitorStore struct{ db *sql.DB }

const createKVTable = `CREATE TABLE IF NOT EXISTS sitemonitor_kv (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
)`

const createSnapshotTable = `CREATE TABLE IF NOT EXISTS sitemonitor_snapshots (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	created_at INTEGER NOT NULL,
	host       TEXT NOT NULL,
	requests   INTEGER NOT NULL,
	bytes      INTEGER NOT NULL,
	report     TEXT NOT NULL
)`

const kvSettings = "settings"

// newMonitorStore 建表(幂等)并返回辅助。
func newMonitorStore(st *store.Store) (*monitorStore, error) {
	if _, err := st.DB.Exec(createKVTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createSnapshotTable); err != nil {
		return nil, err
	}
	if err := initTargetTables(st.DB); err != nil {
		return nil, err
	}
	return &monitorStore{db: st.DB}, nil
}

// getSettings 读单例设置;无记录时返回出厂默认。
func (s *monitorStore) getSettings() (Settings, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM sitemonitor_kv WHERE k = ?`, kvSettings).Scan(&v)
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
func (s *monitorStore) setSettings(set Settings) error {
	v, err := json.Marshal(set)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO sitemonitor_kv (k, v) VALUES (?, ?)
		 ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
		kvSettings, string(v),
	)
	return err
}

// saveSnapshot 落盘一次聚合快照(整 host 概览)。
func (s *monitorStore) saveSnapshot(host string, rep Report) error {
	raw, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(
		`INSERT INTO sitemonitor_snapshots (created_at, host, requests, bytes, report)
		 VALUES (?, ?, ?, ?, ?)`,
		time.Now().Unix(), host, rep.TotalRequests, rep.TotalBytes, string(raw),
	)
	return err
}
