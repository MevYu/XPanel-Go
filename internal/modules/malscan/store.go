package malscan

import (
	"database/sql"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// malStore 是本模块私有的 DB 辅助:自建表,管理设置、扫描任务、命中、隔离与白名单。
// 不动中央 migrations,建表幂等。
type malStore struct{ db *sql.DB }

// Settings 是模块可配置项,存于单行表 malscan_settings (id=1)。
type Settings struct {
	ScanDir       string `json:"scan_dir"`       // 默认扫描根目录
	QuarantineDir string `json:"quarantine_dir"` // 隔离区目录
	MaxFileSize   int64  `json:"max_file_size"`  // 单文件大小上限(字节)
	MaxFiles      int    `json:"max_files"`      // 单次扫描文件数上限
	ScoreToFlag   int    `json:"score_to_flag"`  // 判定可疑的累计分阈值
}

// defaultSettings 是首次建表写入的缺省配置。
func defaultSettings() Settings {
	d := defaultLimits()
	return Settings{
		ScanDir:       "/www/wwwroot",
		QuarantineDir: "/www/xpanel_quarantine",
		MaxFileSize:   d.MaxFileSize,
		MaxFiles:      d.MaxFiles,
		ScoreToFlag:   d.ScoreToFlag,
	}
}

// Task 是一次扫描任务的记录。Status: running|done|failed。
type Task struct {
	ID           int64  `json:"id"`
	Root         string `json:"root"`
	Status       string `json:"status"`
	FilesScanned int    `json:"files_scanned"`
	FilesSkipped int    `json:"files_skipped"`
	FlaggedCount int    `json:"flagged_count"`
	Error        string `json:"error"`
	StartedBy    *int64 `json:"started_by"`
	StartedAt    int64  `json:"started_at"`
	FinishedAt   *int64 `json:"finished_at"`
}

// Hit 是一条命中记录:某任务在某文件某行命中某规则。
type Hit struct {
	ID          int64  `json:"id"`
	TaskID      int64  `json:"task_id"`
	Path        string `json:"path"`
	Score       int    `json:"score"`
	RuleID      string `json:"rule_id"`
	Rule        string `json:"rule"`
	Line        int    `json:"line"`
	Excerpt     string `json:"excerpt"`
	Quarantined bool   `json:"quarantined"` // 该文件是否已被隔离
}

// Quarantine 是一条隔离记录:原路径 -> 隔离区路径,可据此还原。
type Quarantine struct {
	ID            int64  `json:"id"`
	OrigPath      string `json:"orig_path"`
	StoredPath    string `json:"stored_path"`
	QuarantinedBy *int64 `json:"quarantined_by"`
	QuarantinedAt int64  `json:"quarantined_at"`
	Restored      bool   `json:"restored"`
}

const schema = `
CREATE TABLE IF NOT EXISTS malscan_settings (
	id             INTEGER PRIMARY KEY CHECK (id = 1),
	scan_dir       TEXT NOT NULL,
	quarantine_dir TEXT NOT NULL,
	max_file_size  INTEGER NOT NULL,
	max_files      INTEGER NOT NULL,
	score_to_flag  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS malscan_tasks (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	root          TEXT NOT NULL,
	status        TEXT NOT NULL,
	files_scanned INTEGER NOT NULL DEFAULT 0,
	files_skipped INTEGER NOT NULL DEFAULT 0,
	flagged_count INTEGER NOT NULL DEFAULT 0,
	error         TEXT NOT NULL DEFAULT '',
	started_by    INTEGER,
	started_at    INTEGER NOT NULL,
	finished_at   INTEGER
);
CREATE TABLE IF NOT EXISTS malscan_hits (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	task_id     INTEGER NOT NULL,
	path        TEXT NOT NULL,
	score       INTEGER NOT NULL,
	rule_id     TEXT NOT NULL,
	rule        TEXT NOT NULL,
	line        INTEGER NOT NULL,
	excerpt     TEXT NOT NULL DEFAULT '',
	quarantined INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS malscan_quarantine (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	orig_path      TEXT NOT NULL,
	stored_path    TEXT NOT NULL,
	quarantined_by INTEGER,
	quarantined_at INTEGER NOT NULL,
	restored       INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS malscan_whitelist (
	path       TEXT PRIMARY KEY,
	added_by   INTEGER,
	added_at   INTEGER NOT NULL
);`

// newMalStore 建表(幂等)、确保默认设置存在,返回辅助。
func newMalStore(st *store.Store) (*malStore, error) {
	if _, err := st.DB.Exec(schema); err != nil {
		return nil, err
	}
	ms := &malStore{db: st.DB}
	if err := ms.ensureSettings(); err != nil {
		return nil, err
	}
	return ms, nil
}

func (m *malStore) ensureSettings() error {
	var n int
	if err := m.db.QueryRow(`SELECT COUNT(*) FROM malscan_settings WHERE id = 1`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	d := defaultSettings()
	_, err := m.db.Exec(`INSERT INTO malscan_settings
		(id, scan_dir, quarantine_dir, max_file_size, max_files, score_to_flag)
		VALUES (1, ?, ?, ?, ?, ?)`,
		d.ScanDir, d.QuarantineDir, d.MaxFileSize, d.MaxFiles, d.ScoreToFlag)
	return err
}

func (m *malStore) getSettings() (Settings, error) {
	var s Settings
	err := m.db.QueryRow(`SELECT scan_dir, quarantine_dir, max_file_size, max_files, score_to_flag
		FROM malscan_settings WHERE id = 1`).
		Scan(&s.ScanDir, &s.QuarantineDir, &s.MaxFileSize, &s.MaxFiles, &s.ScoreToFlag)
	return s, err
}

func (m *malStore) putSettings(s Settings) error {
	_, err := m.db.Exec(`UPDATE malscan_settings SET
		scan_dir = ?, quarantine_dir = ?, max_file_size = ?, max_files = ?, score_to_flag = ?
		WHERE id = 1`,
		s.ScanDir, s.QuarantineDir, s.MaxFileSize, s.MaxFiles, s.ScoreToFlag)
	return err
}

func (m *malStore) createTask(root string, by *int64) (int64, error) {
	res, err := m.db.Exec(`INSERT INTO malscan_tasks (root, status, started_by, started_at)
		VALUES (?, 'running', ?, ?)`, root, by, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// finishTask 写入终态(done/failed)与统计。
func (m *malStore) finishTask(id int64, status string, rep ScanReport, scanErr string) error {
	now := time.Now().Unix()
	_, err := m.db.Exec(`UPDATE malscan_tasks SET
		status = ?, files_scanned = ?, files_skipped = ?, flagged_count = ?, error = ?, finished_at = ?
		WHERE id = ?`,
		status, rep.FilesScanned, rep.FilesSkipped, len(rep.Flagged), scanErr, now, id)
	return err
}

// insertHits 批量写入一次扫描的命中记录。
func (m *malStore) insertHits(taskID int64, flagged []FileResult) error {
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO malscan_hits
		(task_id, path, score, rule_id, rule, line, excerpt) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, fr := range flagged {
		for _, mt := range fr.Matches {
			if _, err := stmt.Exec(taskID, fr.Path, fr.Score, mt.RuleID, mt.Rule, mt.Line, mt.Excerpt); err != nil {
				_ = tx.Rollback()
				return err
			}
		}
	}
	return tx.Commit()
}

func (m *malStore) listTasks() ([]Task, error) {
	rows, err := m.db.Query(`SELECT id, root, status, files_scanned, files_skipped,
		flagged_count, error, started_by, started_at, finished_at
		FROM malscan_tasks ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ts []Task
	for rows.Next() {
		var t Task
		var startedBy, finishedAt sql.NullInt64
		if err := rows.Scan(&t.ID, &t.Root, &t.Status, &t.FilesScanned, &t.FilesSkipped,
			&t.FlaggedCount, &t.Error, &startedBy, &t.StartedAt, &finishedAt); err != nil {
			return nil, err
		}
		if startedBy.Valid {
			t.StartedBy = &startedBy.Int64
		}
		if finishedAt.Valid {
			t.FinishedAt = &finishedAt.Int64
		}
		ts = append(ts, t)
	}
	return ts, rows.Err()
}

func (m *malStore) listTaskByID(id int64) (Task, error) {
	var t Task
	var startedBy, finishedAt sql.NullInt64
	err := m.db.QueryRow(`SELECT id, root, status, files_scanned, files_skipped,
		flagged_count, error, started_by, started_at, finished_at
		FROM malscan_tasks WHERE id = ?`, id).
		Scan(&t.ID, &t.Root, &t.Status, &t.FilesScanned, &t.FilesSkipped,
			&t.FlaggedCount, &t.Error, &startedBy, &t.StartedAt, &finishedAt)
	if err != nil {
		return Task{}, err
	}
	if startedBy.Valid {
		t.StartedBy = &startedBy.Int64
	}
	if finishedAt.Valid {
		t.FinishedAt = &finishedAt.Int64
	}
	return t, nil
}

func (m *malStore) listHits(taskID int64) ([]Hit, error) {
	rows, err := m.db.Query(`SELECT id, task_id, path, score, rule_id, rule, line, excerpt, quarantined
		FROM malscan_hits WHERE task_id = ? ORDER BY score DESC, path, line`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hs []Hit
	for rows.Next() {
		var h Hit
		var q int
		if err := rows.Scan(&h.ID, &h.TaskID, &h.Path, &h.Score, &h.RuleID, &h.Rule,
			&h.Line, &h.Excerpt, &q); err != nil {
			return nil, err
		}
		h.Quarantined = q != 0
		hs = append(hs, h)
	}
	return hs, rows.Err()
}

// markQuarantined 把命中表中某原路径的所有行标记为已隔离(true)或已还原(false)。
func (m *malStore) markQuarantined(origPath string, q bool) error {
	_, err := m.db.Exec(`UPDATE malscan_hits SET quarantined = ? WHERE path = ?`, boolToInt(q), origPath)
	return err
}

func (m *malStore) addQuarantine(orig, stored string, by *int64) (int64, error) {
	res, err := m.db.Exec(`INSERT INTO malscan_quarantine
		(orig_path, stored_path, quarantined_by, quarantined_at) VALUES (?, ?, ?, ?)`,
		orig, stored, by, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (m *malStore) listQuarantine() ([]Quarantine, error) {
	rows, err := m.db.Query(`SELECT id, orig_path, stored_path, quarantined_by, quarantined_at, restored
		FROM malscan_quarantine WHERE restored = 0 ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var qs []Quarantine
	for rows.Next() {
		var q Quarantine
		var by sql.NullInt64
		var restored int
		if err := rows.Scan(&q.ID, &q.OrigPath, &q.StoredPath, &by, &q.QuarantinedAt, &restored); err != nil {
			return nil, err
		}
		if by.Valid {
			q.QuarantinedBy = &by.Int64
		}
		q.Restored = restored != 0
		qs = append(qs, q)
	}
	return qs, rows.Err()
}

// activeQuarantine 取某原路径未还原的隔离记录(用于移出隔离)。
func (m *malStore) activeQuarantine(origPath string) (Quarantine, error) {
	var q Quarantine
	var by sql.NullInt64
	var restored int
	err := m.db.QueryRow(`SELECT id, orig_path, stored_path, quarantined_by, quarantined_at, restored
		FROM malscan_quarantine WHERE orig_path = ? AND restored = 0 ORDER BY id DESC LIMIT 1`, origPath).
		Scan(&q.ID, &q.OrigPath, &q.StoredPath, &by, &q.QuarantinedAt, &restored)
	if err != nil {
		return Quarantine{}, err
	}
	if by.Valid {
		q.QuarantinedBy = &by.Int64
	}
	q.Restored = restored != 0
	return q, nil
}

func (m *malStore) markRestored(id int64) error {
	_, err := m.db.Exec(`UPDATE malscan_quarantine SET restored = 1 WHERE id = ?`, id)
	return err
}

func (m *malStore) addWhitelist(path string, by *int64) error {
	_, err := m.db.Exec(`INSERT INTO malscan_whitelist (path, added_by, added_at)
		VALUES (?, ?, ?) ON CONFLICT(path) DO NOTHING`, path, by, time.Now().Unix())
	return err
}

func (m *malStore) removeWhitelist(path string) error {
	_, err := m.db.Exec(`DELETE FROM malscan_whitelist WHERE path = ?`, path)
	return err
}

func (m *malStore) whitelist() (map[string]bool, error) {
	rows, err := m.db.Query(`SELECT path FROM malscan_whitelist`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	set := map[string]bool{}
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		set[p] = true
	}
	return set, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
