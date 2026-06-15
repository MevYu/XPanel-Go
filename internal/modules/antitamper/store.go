package antitamper

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Settings 是模块可配置项,存于单行表 antitamper_settings (id=1)。
// ProtectedDirs/ExcludeRules 以 JSON 数组落库。
type Settings struct {
	ProtectedDirs []string `json:"protected_dirs"` // 受保护目录(绝对路径列表)
	ExcludeRules  []string `json:"exclude_rules"`  // 排除规则(filepath.Match 语义)
	IntervalSec   int      `json:"interval_sec"`   // 扫描间隔(秒)
	Paused        bool     `json:"paused"`         // 暂停保护:为真时后台扫描跳过对比/记事件
}

// defaultSettings 是首次建表写入的缺省配置。
func defaultSettings() Settings {
	return Settings{
		ProtectedDirs: []string{"/www/wwwroot"},
		ExcludeRules:  []string{"*.log", "*.tmp", "cache", ".git"},
		IntervalSec:   300,
		Paused:        false,
	}
}

// Event 是一条篡改事件记录。
type Event struct {
	ID         int64      `json:"id"`
	Path       string     `json:"path"`
	Type       ChangeType `json:"type"`
	OldHash    string     `json:"old_hash"`
	NewHash    string     `json:"new_hash"`
	DetectedAt int64      `json:"detected_at"`
}

const schema = `
CREATE TABLE IF NOT EXISTS antitamper_settings (
	id             INTEGER PRIMARY KEY CHECK (id = 1),
	protected_dirs TEXT NOT NULL,
	exclude_rules  TEXT NOT NULL,
	interval_sec   INTEGER NOT NULL,
	paused         INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS antitamper_baseline (
	path  TEXT PRIMARY KEY,
	hash  TEXT NOT NULL,
	mtime INTEGER NOT NULL,
	mode  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS antitamper_events (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	path        TEXT NOT NULL,
	type        TEXT NOT NULL,
	old_hash    TEXT NOT NULL DEFAULT '',
	new_hash    TEXT NOT NULL DEFAULT '',
	detected_at INTEGER NOT NULL
);`

// atStore 是本模块私有的 DB 辅助:自建表,管理设置、基线与篡改事件。
// 不动中央 migrations,建表幂等。
type atStore struct{ db *sql.DB }

// newATStore 建表(幂等)、确保默认设置存在,返回辅助。
func newATStore(st *store.Store) (*atStore, error) {
	if _, err := st.DB.Exec(schema); err != nil {
		return nil, err
	}
	s := &atStore{db: st.DB}
	if err := s.ensureSettings(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *atStore) ensureSettings() error {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM antitamper_settings WHERE id = 1`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	return s.putSettings(defaultSettings())
}

func (s *atStore) getSettings() (Settings, error) {
	var out Settings
	var dirs, rules string
	var paused int
	err := s.db.QueryRow(`SELECT protected_dirs, exclude_rules, interval_sec, paused
		FROM antitamper_settings WHERE id = 1`).Scan(&dirs, &rules, &out.IntervalSec, &paused)
	if err != nil {
		return Settings{}, err
	}
	if err := json.Unmarshal([]byte(dirs), &out.ProtectedDirs); err != nil {
		return Settings{}, err
	}
	if err := json.Unmarshal([]byte(rules), &out.ExcludeRules); err != nil {
		return Settings{}, err
	}
	out.Paused = paused != 0
	return out, nil
}

func (s *atStore) putSettings(in Settings) error {
	dirs, err := json.Marshal(orEmpty(in.ProtectedDirs))
	if err != nil {
		return err
	}
	rules, err := json.Marshal(orEmpty(in.ExcludeRules))
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO antitamper_settings (id, protected_dirs, exclude_rules, interval_sec, paused)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 protected_dirs=excluded.protected_dirs, exclude_rules=excluded.exclude_rules,
		 interval_sec=excluded.interval_sec, paused=excluded.paused`,
		string(dirs), string(rules), in.IntervalSec, boolToInt(in.Paused))
	return err
}

// setPaused 仅更新暂停标志(暂停/恢复保护)。
func (s *atStore) setPaused(p bool) error {
	_, err := s.db.Exec(`UPDATE antitamper_settings SET paused = ? WHERE id = 1`, boolToInt(p))
	return err
}

// replaceBaseline 用 states 全量替换基线(重建基线)。事务保证原子。
func (s *atStore) replaceBaseline(states map[string]FileState) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM antitamper_baseline`); err != nil {
		_ = tx.Rollback()
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO antitamper_baseline (path, hash, mtime, mode) VALUES (?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, st := range states {
		if _, err := stmt.Exec(st.Path, st.Hash, st.MTime, st.Mode); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// baseline 读出全部基线指纹(以绝对路径为键)。
func (s *atStore) baseline() (map[string]FileState, error) {
	rows, err := s.db.Query(`SELECT path, hash, mtime, mode FROM antitamper_baseline`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]FileState{}
	for rows.Next() {
		var st FileState
		if err := rows.Scan(&st.Path, &st.Hash, &st.MTime, &st.Mode); err != nil {
			return nil, err
		}
		out[st.Path] = st
	}
	return out, rows.Err()
}

// applyChanges 把检出的变更并入基线:added/modified 更新指纹,deleted 删除条目。
// 这样下一轮不会对同一变更重复告警(每次篡改只记一次事件)。
func (s *atStore) applyChanges(cur map[string]FileState, changes []Change) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, c := range changes {
		switch c.Type {
		case ChangeDeleted:
			if _, err := tx.Exec(`DELETE FROM antitamper_baseline WHERE path = ?`, c.Path); err != nil {
				_ = tx.Rollback()
				return err
			}
		case ChangeAdded, ChangeModified:
			st := cur[c.Path]
			if _, err := tx.Exec(`INSERT INTO antitamper_baseline (path, hash, mtime, mode)
				VALUES (?, ?, ?, ?)
				ON CONFLICT(path) DO UPDATE SET hash=excluded.hash, mtime=excluded.mtime, mode=excluded.mode`,
				st.Path, st.Hash, st.MTime, st.Mode); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

// recordEvents 批量写入篡改事件。
func (s *atStore) recordEvents(changes []Change) error {
	if len(changes) == 0 {
		return nil
	}
	now := time.Now().Unix()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO antitamper_events (path, type, old_hash, new_hash, detected_at)
		VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, c := range changes {
		if _, err := stmt.Exec(c.Path, string(c.Type), c.OldHash, c.NewHash, now); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// listEvents 返回最近的篡改事件(最多 limit 条,按时间倒序)。
func (s *atStore) listEvents(limit int) ([]Event, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	rows, err := s.db.Query(`SELECT id, path, type, old_hash, new_hash, detected_at
		FROM antitamper_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var typ string
		if err := rows.Scan(&e.ID, &e.Path, &typ, &e.OldHash, &e.NewHash, &e.DetectedAt); err != nil {
			return nil, err
		}
		e.Type = ChangeType(typ)
		out = append(out, e)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// orEmpty 把 nil 切片归一为空切片,保证 JSON 落库为 "[]" 而非 "null"。
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
