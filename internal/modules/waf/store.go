package waf

import (
	"database/sql"
	"encoding/json"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// wafStore 是本模块私有的 DB 辅助:自建表,不动中央 migrations,建表幂等。
type wafStore struct{ db *sql.DB }

const createIPTable = `CREATE TABLE IF NOT EXISTS waf_ip_rules (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	action  TEXT NOT NULL,
	cidr    TEXT NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1
)`

const createMatchTable = `CREATE TABLE IF NOT EXISTS waf_match_rules (
	id      INTEGER PRIMARY KEY AUTOINCREMENT,
	target  TEXT NOT NULL,
	pattern TEXT NOT NULL,
	action  TEXT NOT NULL,
	comment TEXT NOT NULL DEFAULT '',
	enabled INTEGER NOT NULL DEFAULT 1
)`

// waf_kv 存单例配置(CC、Settings)为 JSON,key 唯一。
const createKVTable = `CREATE TABLE IF NOT EXISTS waf_kv (
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
)`

const (
	kvCC       = "cc"
	kvSettings = "settings"
)

// newWAFStore 建三张表(幂等)并返回辅助。
func newWAFStore(st *store.Store) (*wafStore, error) {
	for _, q := range []string{createIPTable, createMatchTable, createKVTable} {
		if _, err := st.DB.Exec(q); err != nil {
			return nil, err
		}
	}
	return &wafStore{db: st.DB}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- IP rules ---

func (s *wafStore) listIP() ([]IPRule, error) {
	rows, err := s.db.Query(`SELECT id, action, cidr, comment, enabled FROM waf_ip_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPRule
	for rows.Next() {
		var r IPRule
		var en int
		if err := rows.Scan(&r.ID, &r.Action, &r.CIDR, &r.Comment, &en); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *wafStore) createIP(r IPRule) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO waf_ip_rules (action, cidr, comment, enabled) VALUES (?, ?, ?, ?)`,
		r.Action, r.CIDR, r.Comment, boolToInt(r.Enabled))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *wafStore) deleteIP(id int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM waf_ip_rules WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- Match rules ---

func (s *wafStore) listMatch() ([]MatchRule, error) {
	rows, err := s.db.Query(`SELECT id, target, pattern, action, comment, enabled FROM waf_match_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []MatchRule
	for rows.Next() {
		var r MatchRule
		var en int
		if err := rows.Scan(&r.ID, &r.Target, &r.Pattern, &r.Action, &r.Comment, &en); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *wafStore) createMatch(r MatchRule) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO waf_match_rules (target, pattern, action, comment, enabled) VALUES (?, ?, ?, ?, ?)`,
		r.Target, r.Pattern, r.Action, r.Comment, boolToInt(r.Enabled))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *wafStore) deleteMatch(id int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM waf_match_rules WHERE id = ?`, id)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// --- KV singletons (CC, Settings) ---

// getCC 返回存储的 CC 配置;无记录时返回 DefaultCCConfig。
func (s *wafStore) getCC() (CCConfig, error) {
	v, ok, err := s.getKV(kvCC)
	if err != nil || !ok {
		return DefaultCCConfig(), err
	}
	var cc CCConfig
	if err := json.Unmarshal([]byte(v), &cc); err != nil {
		return DefaultCCConfig(), err
	}
	return cc, nil
}

func (s *wafStore) setCC(cc CCConfig) error {
	b, err := json.Marshal(cc)
	if err != nil {
		return err
	}
	return s.setKV(kvCC, string(b))
}

// getSettings 返回存储的设置;无记录时返回 DefaultSettings。
func (s *wafStore) getSettings() (Settings, error) {
	v, ok, err := s.getKV(kvSettings)
	if err != nil || !ok {
		return DefaultSettings(), err
	}
	var st Settings
	if err := json.Unmarshal([]byte(v), &st); err != nil {
		return DefaultSettings(), err
	}
	return st, nil
}

func (s *wafStore) setSettings(st Settings) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return s.setKV(kvSettings, string(b))
}

func (s *wafStore) getKV(k string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT v FROM waf_kv WHERE k = ?`, k).Scan(&v)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return v, true, nil
}

func (s *wafStore) setKV(k, v string) error {
	_, err := s.db.Exec(`INSERT INTO waf_kv (k, v) VALUES (?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	return err
}
