package cron

import (
	"database/sql"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// cronStore 是本模块私有的 DB 辅助:自建表,管理 cron 任务元数据。
// 不动中央 migrations,建表幂等。
type cronStore struct{ db *sql.DB }

// Job 是一条 cron 任务的元数据。Enabled 决定是否写入真实 crontab。
type Job struct {
	ID         int64  `json:"id"`
	Expr       string `json:"expr"`
	Command    string `json:"command"`
	Comment    string `json:"comment"`
	Enabled    bool   `json:"enabled"`
	CreatedBy  *int64 `json:"created_by"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
	LastRunAt  *int64 `json:"last_run_at"`
	LastResult string `json:"last_result"`
}

const createCronTable = `CREATE TABLE IF NOT EXISTS cron_jobs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	expr        TEXT NOT NULL,
	command     TEXT NOT NULL,
	comment     TEXT NOT NULL DEFAULT '',
	enabled     INTEGER NOT NULL DEFAULT 1,
	created_by  INTEGER,
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL,
	last_run_at INTEGER,
	last_result TEXT NOT NULL DEFAULT ''
)`

// newCronStore 建表(幂等)并返回辅助。
func newCronStore(st *store.Store) (*cronStore, error) {
	if _, err := st.DB.Exec(createCronTable); err != nil {
		return nil, err
	}
	return &cronStore{db: st.DB}, nil
}

func (c *cronStore) list() ([]Job, error) {
	rows, err := c.db.Query(`SELECT id, expr, command, comment, enabled, created_by,
		created_at, updated_at, last_run_at, last_result FROM cron_jobs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var jobs []Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// enabled 返回所有启用的任务,供生成 crontab 托管区。
func (c *cronStore) enabled() ([]Job, error) {
	all, err := c.list()
	if err != nil {
		return nil, err
	}
	var on []Job
	for _, j := range all {
		if j.Enabled {
			on = append(on, j)
		}
	}
	return on, nil
}

func (c *cronStore) get(id int64) (Job, error) {
	row := c.db.QueryRow(`SELECT id, expr, command, comment, enabled, created_by,
		created_at, updated_at, last_run_at, last_result FROM cron_jobs WHERE id = ?`, id)
	return scanJob(row)
}

func (c *cronStore) create(j Job) (int64, error) {
	now := time.Now().Unix()
	res, err := c.db.Exec(`INSERT INTO cron_jobs
		(expr, command, comment, enabled, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		j.Expr, j.Command, j.Comment, boolToInt(j.Enabled), j.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (c *cronStore) update(id int64, expr, command, comment string) error {
	_, err := c.db.Exec(`UPDATE cron_jobs SET expr = ?, command = ?, comment = ?, updated_at = ?
		WHERE id = ?`, expr, command, comment, time.Now().Unix(), id)
	return err
}

func (c *cronStore) setEnabled(id int64, enabled bool) error {
	_, err := c.db.Exec(`UPDATE cron_jobs SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), time.Now().Unix(), id)
	return err
}

func (c *cronStore) delete(id int64) error {
	_, err := c.db.Exec(`DELETE FROM cron_jobs WHERE id = ?`, id)
	return err
}

// scanner 抽象 *sql.Row 与 *sql.Rows 的共同 Scan 方法。
type scanner interface {
	Scan(dest ...any) error
}

func scanJob(s scanner) (Job, error) {
	var j Job
	var enabled int
	var createdBy, lastRunAt sql.NullInt64
	err := s.Scan(&j.ID, &j.Expr, &j.Command, &j.Comment, &enabled,
		&createdBy, &j.CreatedAt, &j.UpdatedAt, &lastRunAt, &j.LastResult)
	if err != nil {
		return Job{}, err
	}
	j.Enabled = enabled != 0
	if createdBy.Valid {
		j.CreatedBy = &createdBy.Int64
	}
	if lastRunAt.Valid {
		j.LastRunAt = &lastRunAt.Int64
	}
	return j, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
