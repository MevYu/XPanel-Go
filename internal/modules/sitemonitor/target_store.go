package sitemonitor

import (
	"database/sql"
	"errors"
	"time"
)

// errTargetNotFound 表示按 id 找不到目标(供 handler 映射 404)。
var errTargetNotFound = errors.New("target not found")

const createTargetsTable = `CREATE TABLE IF NOT EXISTS monitor_targets (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	name         TEXT NOT NULL,
	url          TEXT NOT NULL,
	interval_sec INTEGER NOT NULL,
	timeout_sec  INTEGER NOT NULL,
	enabled      INTEGER NOT NULL,
	created_at   INTEGER NOT NULL
)`

const createResultsTable = `CREATE TABLE IF NOT EXISTS monitor_results (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	target_id   INTEGER NOT NULL,
	checked_at  INTEGER NOT NULL,
	up          INTEGER NOT NULL,
	status_code INTEGER NOT NULL,
	latency_ms  INTEGER NOT NULL,
	error       TEXT NOT NULL
)`

const createResultsIndex = `CREATE INDEX IF NOT EXISTS idx_monitor_results_target
	ON monitor_results (target_id, id)`

// initTargetTables 幂等建探测目标与结果表。
func initTargetTables(db *sql.DB) error {
	for _, q := range []string{createTargetsTable, createResultsTable, createResultsIndex} {
		if _, err := db.Exec(q); err != nil {
			return err
		}
	}
	return nil
}

// createTarget 插入新目标,返回带 id/created_at 的完整记录。
func (s *monitorStore) createTarget(in targetInput) (Target, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(
		`INSERT INTO monitor_targets (name, url, interval_sec, timeout_sec, enabled, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		in.normalizedName(), in.URL, in.IntervalSec, in.TimeoutSec, boolToInt(in.Enabled), now,
	)
	if err != nil {
		return Target{}, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return Target{}, err
	}
	return Target{
		ID:          id,
		Name:        in.normalizedName(),
		URL:         in.URL,
		IntervalSec: in.IntervalSec,
		TimeoutSec:  in.TimeoutSec,
		Enabled:     in.Enabled,
		CreatedAt:   now,
	}, nil
}

// updateTarget 全量更新目标字段;目标不存在返回 errTargetNotFound。
func (s *monitorStore) updateTarget(id int64, in targetInput) (Target, error) {
	res, err := s.db.Exec(
		`UPDATE monitor_targets
		 SET name = ?, url = ?, interval_sec = ?, timeout_sec = ?, enabled = ?
		 WHERE id = ?`,
		in.normalizedName(), in.URL, in.IntervalSec, in.TimeoutSec, boolToInt(in.Enabled), id,
	)
	if err != nil {
		return Target{}, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return Target{}, err
	}
	if n == 0 {
		return Target{}, errTargetNotFound
	}
	return s.getTarget(id)
}

// deleteTarget 删除目标及其全部探测结果;目标不存在返回 errTargetNotFound。
func (s *monitorStore) deleteTarget(id int64) error {
	res, err := s.db.Exec(`DELETE FROM monitor_targets WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return errTargetNotFound
	}
	_, err = s.db.Exec(`DELETE FROM monitor_results WHERE target_id = ?`, id)
	return err
}

// getTarget 按 id 取单个目标;不存在返回 errTargetNotFound。
func (s *monitorStore) getTarget(id int64) (Target, error) {
	var t Target
	var enabled int
	err := s.db.QueryRow(
		`SELECT id, name, url, interval_sec, timeout_sec, enabled, created_at
		 FROM monitor_targets WHERE id = ?`, id,
	).Scan(&t.ID, &t.Name, &t.URL, &t.IntervalSec, &t.TimeoutSec, &enabled, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return Target{}, errTargetNotFound
	}
	if err != nil {
		return Target{}, err
	}
	t.Enabled = enabled != 0
	return t, nil
}

// listTargets 返回所有目标(按 id 升序)。
func (s *monitorStore) listTargets() ([]Target, error) {
	rows, err := s.db.Query(
		`SELECT id, name, url, interval_sec, timeout_sec, enabled, created_at
		 FROM monitor_targets ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Target, 0)
	for rows.Next() {
		var t Target
		var enabled int
		if err := rows.Scan(&t.ID, &t.Name, &t.URL, &t.IntervalSec, &t.TimeoutSec, &enabled, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.Enabled = enabled != 0
		out = append(out, t)
	}
	return out, rows.Err()
}

// insertResult 落盘一次探测结果,并裁剪该目标超过 maxResultsPerTarget 的最老记录。
func (s *monitorStore) insertResult(res Result) error {
	if _, err := s.db.Exec(
		`INSERT INTO monitor_results (target_id, checked_at, up, status_code, latency_ms, error)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		res.TargetID, res.CheckedAt, boolToInt(res.Up), res.StatusCode, res.LatencyMS, res.Err,
	); err != nil {
		return err
	}
	// 保留最近 maxResultsPerTarget 条:删掉 id 不在最新窗口内的旧记录。
	_, err := s.db.Exec(
		`DELETE FROM monitor_results
		 WHERE target_id = ? AND id NOT IN (
		   SELECT id FROM monitor_results WHERE target_id = ? ORDER BY id DESC LIMIT ?
		 )`,
		res.TargetID, res.TargetID, maxResultsPerTarget,
	)
	return err
}

// summary 算单个目标的最近探测摘要与可用率(基于保留窗口内的全部结果)。
func (s *monitorStore) summary(targetID int64) (lastStatus string, lastCode int, lastLatency int64, lastAt int64, availability float64, err error) {
	rows, qerr := s.db.Query(
		`SELECT up, status_code, latency_ms, checked_at
		 FROM monitor_results WHERE target_id = ? ORDER BY id DESC`, targetID,
	)
	if qerr != nil {
		return "", 0, 0, 0, 0, qerr
	}
	defer rows.Close()
	var total, upCount int
	first := true
	for rows.Next() {
		var up, code int
		var latency, at int64
		if serr := rows.Scan(&up, &code, &latency, &at); serr != nil {
			return "", 0, 0, 0, 0, serr
		}
		if first {
			if up != 0 {
				lastStatus = "up"
			} else {
				lastStatus = "down"
			}
			lastCode, lastLatency, lastAt = code, latency, at
			first = false
		}
		total++
		if up != 0 {
			upCount++
		}
	}
	if rerr := rows.Err(); rerr != nil {
		return "", 0, 0, 0, 0, rerr
	}
	if total == 0 {
		return "unknown", 0, 0, 0, 0, nil
	}
	return lastStatus, lastCode, lastLatency, lastAt, float64(upCount) / float64(total), nil
}

// targetView 取目标 + 摘要组装成视图。
func (s *monitorStore) targetView(t Target) (TargetView, error) {
	status, code, latency, at, avail, err := s.summary(t.ID)
	if err != nil {
		return TargetView{}, err
	}
	return TargetView{
		Target:        t,
		LastStatus:    status,
		LastCode:      code,
		LastLatencyMS: latency,
		LastCheckedAt: at,
		Availability:  avail,
	}, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
