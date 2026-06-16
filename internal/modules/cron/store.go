package cron

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// cronStore 是本模块私有的 DB 辅助:自建表,管理 cron 任务元数据与执行日志。
// 不动中央 migrations,建表/加列幂等。
type cronStore struct{ db *sql.DB }

// Job 是一条 cron 任务的元数据。Enabled 决定是否写入真实 crontab。
// Type/Payload 描述任务类型与参数;旧库迁移上来默认 Type=command,Payload.Command=Command。
type Job struct {
	ID         int64   `json:"id"`
	Expr       string  `json:"expr"`
	Type       string  `json:"type"`
	Payload    payload `json:"payload"`
	Command    string  `json:"command"` // 渲染进 crontab 的等价命令(展示用,由类型派生)
	Comment    string  `json:"comment"`
	Enabled    bool    `json:"enabled"`
	CreatedBy  *int64  `json:"created_by"`
	CreatedAt  int64   `json:"created_at"`
	UpdatedAt  int64   `json:"updated_at"`
	LastRunAt  *int64  `json:"last_run_at"`
	LastResult string  `json:"last_result"`
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

const createRunsTable = `CREATE TABLE IF NOT EXISTS cron_runs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	job_id      INTEGER NOT NULL,
	started_at  INTEGER NOT NULL,
	duration_ms INTEGER NOT NULL,
	exit_code   INTEGER NOT NULL,
	output      TEXT NOT NULL DEFAULT '',
	err         TEXT NOT NULL DEFAULT ''
)`

// maxRunsPerJob 是每任务保留的执行记录上限(最近 N 次)。
const maxRunsPerJob = 50

// newCronStore 建表(幂等)、补列、返回辅助。
func newCronStore(st *store.Store) (*cronStore, error) {
	if _, err := st.DB.Exec(createCronTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createRunsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_cron_runs_job ON cron_runs(job_id, id)`); err != nil {
		return nil, err
	}
	// 旧库补列:type/payload。SQLite 无 IF NOT EXISTS,忽略 duplicate column 错误。
	addColumn(st.DB, `ALTER TABLE cron_jobs ADD COLUMN type TEXT NOT NULL DEFAULT 'command'`)
	addColumn(st.DB, `ALTER TABLE cron_jobs ADD COLUMN payload TEXT NOT NULL DEFAULT '{}'`)
	return &cronStore{db: st.DB}, nil
}

// addColumn 执行 ALTER TABLE ADD COLUMN,忽略列已存在的错误(幂等迁移)。
func addColumn(db *sql.DB, stmt string) {
	_, _ = db.Exec(stmt) // 列已存在时报错,无害忽略
}

const jobCols = `id, expr, type, payload, command, comment, enabled, created_by,
	created_at, updated_at, last_run_at, last_result`

func (c *cronStore) list() ([]Job, error) {
	rows, err := c.db.Query(`SELECT ` + jobCols + ` FROM cron_jobs ORDER BY id`)
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

// enabled 返回所有启用的任务,供生成 crontab 托管区与调度。
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
	row := c.db.QueryRow(`SELECT `+jobCols+` FROM cron_jobs WHERE id = ?`, id)
	return scanJob(row)
}

func (c *cronStore) create(j Job) (int64, error) {
	now := time.Now().Unix()
	res, err := c.db.Exec(`INSERT INTO cron_jobs
		(expr, type, payload, command, comment, enabled, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		j.Expr, j.Type, marshalPayload(j.Payload), j.Command, j.Comment,
		boolToInt(j.Enabled), j.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (c *cronStore) update(id int64, j Job) error {
	_, err := c.db.Exec(`UPDATE cron_jobs
		SET expr = ?, type = ?, payload = ?, command = ?, comment = ?, updated_at = ?
		WHERE id = ?`,
		j.Expr, j.Type, marshalPayload(j.Payload), j.Command, j.Comment, time.Now().Unix(), id)
	return err
}

func (c *cronStore) setEnabled(id int64, enabled bool) error {
	_, err := c.db.Exec(`UPDATE cron_jobs SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), time.Now().Unix(), id)
	return err
}

func (c *cronStore) delete(id int64) error {
	if _, err := c.db.Exec(`DELETE FROM cron_runs WHERE job_id = ?`, id); err != nil {
		return err
	}
	_, err := c.db.Exec(`DELETE FROM cron_jobs WHERE id = ?`, id)
	return err
}

// runRecord 是一条执行日志。
type runRecord struct {
	ID         int64  `json:"id"`
	JobID      int64  `json:"job_id"`
	StartedAt  int64  `json:"started_at"`
	DurationMs int64  `json:"duration_ms"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	Err        string `json:"err"`
}

// recordRun 写入一次执行记录,更新任务的 last_run_at/last_result,并裁剪到最近 N 条。
func (c *cronStore) recordRun(jobID int64, r runResult) error {
	if _, err := c.db.Exec(`INSERT INTO cron_runs
		(job_id, started_at, duration_ms, exit_code, output, err)
		VALUES (?, ?, ?, ?, ?, ?)`,
		jobID, r.StartedAt, r.DurationMs, r.ExitCode, r.Output, r.Err); err != nil {
		return err
	}
	summary := "exit " + itoaInt(r.ExitCode)
	if r.Err != "" {
		summary = "error: " + r.Err
	}
	if _, err := c.db.Exec(`UPDATE cron_jobs SET last_run_at = ?, last_result = ? WHERE id = ?`,
		r.StartedAt, summary, jobID); err != nil {
		return err
	}
	// 裁剪:保留 id 最大的 maxRunsPerJob 条。
	_, err := c.db.Exec(`DELETE FROM cron_runs WHERE job_id = ? AND id NOT IN (
		SELECT id FROM cron_runs WHERE job_id = ? ORDER BY id DESC LIMIT ?)`,
		jobID, jobID, maxRunsPerJob)
	return err
}

// runs 返回某任务最近的执行记录(降序,最多 limit 条)。
func (c *cronStore) runs(jobID int64, limit int) ([]runRecord, error) {
	if limit <= 0 || limit > maxRunsPerJob {
		limit = maxRunsPerJob
	}
	rows, err := c.db.Query(`SELECT id, job_id, started_at, duration_ms, exit_code, output, err
		FROM cron_runs WHERE job_id = ? ORDER BY id DESC LIMIT ?`, jobID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []runRecord
	for rows.Next() {
		var r runRecord
		if err := rows.Scan(&r.ID, &r.JobID, &r.StartedAt, &r.DurationMs, &r.ExitCode, &r.Output, &r.Err); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// scanner 抽象 *sql.Row 与 *sql.Rows 的共同 Scan 方法。
type scanner interface {
	Scan(dest ...any) error
}

func scanJob(s scanner) (Job, error) {
	var j Job
	var enabled int
	var payloadJSON string
	var createdBy, lastRunAt sql.NullInt64
	err := s.Scan(&j.ID, &j.Expr, &j.Type, &payloadJSON, &j.Command, &j.Comment, &enabled,
		&createdBy, &j.CreatedAt, &j.UpdatedAt, &lastRunAt, &j.LastResult)
	if err != nil {
		return Job{}, err
	}
	j.Enabled = enabled != 0
	j.Payload = unmarshalPayload(payloadJSON)
	if createdBy.Valid {
		j.CreatedBy = &createdBy.Int64
	}
	if lastRunAt.Valid {
		j.LastRunAt = &lastRunAt.Int64
	}
	return j, nil
}

func marshalPayload(p payload) string {
	b, err := json.Marshal(p)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func unmarshalPayload(s string) payload {
	var p payload
	if s == "" {
		return p
	}
	_ = json.Unmarshal([]byte(s), &p)
	return p
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
