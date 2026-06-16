//go:build fleet

package fleet

import (
	"database/sql"
	"strings"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// 节点状态。pending 节点零权限,不接收任何命令;active 才可被纳管下发。
const (
	nodePending = "pending"
	nodeActive  = "active"
)

// 单节点任务结果状态。
const (
	resultPending = "pending"
	resultRunning = "running"
	resultSuccess = "success"
	resultFailed  = "failed"
	resultTimeout = "timeout"
)

// Node 是一台被纳管的 agent 机器。
type Node struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Tags       string `json:"tags"` // 逗号分隔
	Version    string `json:"version"`
	Status     string `json:"status"`
	LastSeen   int64  `json:"last_seen"`
	EnrolledAt int64  `json:"enrolled_at"`
}

// Job 是一次扇出命令。Argv 为参数数组(JSON 编码),绝不拼 shell。
type Job struct {
	ID         int64  `json:"id"`
	Argv       string `json:"argv"`     // JSON 数组
	Selector   string `json:"selector"` // all | tag:<t> | ids:<id,id>
	TimeoutSec int    `json:"timeout_sec"`
	CreatedBy  *int64 `json:"created_by"`
	CreatedAt  int64  `json:"created_at"`
}

// JobResult 是一个目标节点的执行结果。
type JobResult struct {
	JobID      int64  `json:"job_id"`
	NodeID     string `json:"node_id"`
	Status     string `json:"status"`
	ExitCode   int    `json:"exit_code"`
	Output     string `json:"output"`
	DurationMs int64  `json:"duration_ms"`
	FinishedAt *int64 `json:"finished_at"`
}

// fleetStore 自建 fleet_* 表(幂等),不动中央 migrations。
type fleetStore struct{ db *sql.DB }

const createTables = `
CREATE TABLE IF NOT EXISTS fleet_nodes (
	id          TEXT PRIMARY KEY,
	name        TEXT NOT NULL DEFAULT '',
	tags        TEXT NOT NULL DEFAULT '',
	version     TEXT NOT NULL DEFAULT '',
	status      TEXT NOT NULL DEFAULT 'pending',
	last_seen   INTEGER NOT NULL DEFAULT 0,
	enrolled_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_enroll_tokens (
	token      TEXT PRIMARY KEY,
	created_at INTEGER NOT NULL,
	used_at    INTEGER
);
CREATE TABLE IF NOT EXISTS fleet_jobs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	argv        TEXT NOT NULL,
	selector    TEXT NOT NULL,
	timeout_sec INTEGER NOT NULL,
	created_by  INTEGER,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS fleet_job_results (
	job_id      INTEGER NOT NULL,
	node_id     TEXT NOT NULL,
	status      TEXT NOT NULL,
	exit_code   INTEGER NOT NULL DEFAULT 0,
	output      TEXT NOT NULL DEFAULT '',
	duration_ms INTEGER NOT NULL DEFAULT 0,
	finished_at INTEGER,
	PRIMARY KEY (job_id, node_id)
);
CREATE TABLE IF NOT EXISTS fleet_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
);`

func newFleetStore(st *store.Store) (*fleetStore, error) {
	if _, err := st.DB.Exec(createTables); err != nil {
		return nil, err
	}
	return &fleetStore{db: st.DB}, nil
}

// getOrCreateSecret 返回持久化的 NATS 连接密钥;不存在则用 gen() 生成并存。
// 保证 controller 重启后 agent 仍可用同一密钥连入。
func (s *fleetStore) getOrCreateSecret(gen func() string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM fleet_settings WHERE key = 'nats_secret'`).Scan(&v)
	if err == nil {
		return v, nil
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	v = gen()
	if _, err := s.db.Exec(`INSERT INTO fleet_settings (key, value) VALUES ('nats_secret', ?)`, v); err != nil {
		return "", err
	}
	return v, nil
}

// --- enroll tokens ---

func (s *fleetStore) createEnrollToken(token string) error {
	_, err := s.db.Exec(`INSERT INTO fleet_enroll_tokens (token, created_at) VALUES (?, ?)`,
		token, time.Now().Unix())
	return err
}

// consumeEnrollToken 原子地把未用 token 标为已用,返回是否成功(一次性)。
func (s *fleetStore) consumeEnrollToken(token string) (bool, error) {
	res, err := s.db.Exec(`UPDATE fleet_enroll_tokens SET used_at = ?
		WHERE token = ? AND used_at IS NULL`, time.Now().Unix(), token)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// --- nodes ---

// upsertNode 注册或更新节点。已存在则只更新易变字段(name/tags/version),保留 status。
func (s *fleetStore) upsertNode(n Node) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`INSERT INTO fleet_nodes (id, name, tags, version, status, last_seen, enrolled_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, tags=excluded.tags, version=excluded.version`,
		n.ID, n.Name, n.Tags, n.Version, nodePending, now, now)
	return err
}

func (s *fleetStore) getNode(id string) (Node, error) {
	row := s.db.QueryRow(`SELECT id, name, tags, version, status, last_seen, enrolled_at
		FROM fleet_nodes WHERE id = ?`, id)
	return scanNode(row)
}

func (s *fleetStore) listNodes() ([]Node, error) {
	rows, err := s.db.Query(`SELECT id, name, tags, version, status, last_seen, enrolled_at
		FROM fleet_nodes ORDER BY enrolled_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Node{}
	for rows.Next() {
		n, err := scanNode(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

func (s *fleetStore) approveNode(id string) error {
	_, err := s.db.Exec(`UPDATE fleet_nodes SET status = ? WHERE id = ?`, nodeActive, id)
	return err
}

func (s *fleetStore) deleteNode(id string) error {
	_, err := s.db.Exec(`DELETE FROM fleet_nodes WHERE id = ?`, id)
	return err
}

func (s *fleetStore) touchNode(id string, lastSeen int64) error {
	_, err := s.db.Exec(`UPDATE fleet_nodes SET last_seen = ? WHERE id = ?`, lastSeen, id)
	return err
}

// activeTargets 解析选择器为 active 节点 ID 集合。
// selector: "all" | "tag:<t>" | "ids:<id>,<id>".
func (s *fleetStore) activeTargets(selector string) ([]string, error) {
	all, err := s.listNodes()
	if err != nil {
		return nil, err
	}
	active := map[string]Node{}
	for _, n := range all {
		if n.Status == nodeActive {
			active[n.ID] = n
		}
	}
	out := []string{}
	switch {
	case selector == "all":
		for id := range active {
			out = append(out, id)
		}
	case strings.HasPrefix(selector, "tag:"):
		want := strings.TrimPrefix(selector, "tag:")
		for id, n := range active {
			if hasTag(n.Tags, want) {
				out = append(out, id)
			}
		}
	case strings.HasPrefix(selector, "ids:"):
		for _, id := range strings.Split(strings.TrimPrefix(selector, "ids:"), ",") {
			id = strings.TrimSpace(id)
			if _, ok := active[id]; ok {
				out = append(out, id)
			}
		}
	}
	return out, nil
}

func hasTag(tags, want string) bool {
	for _, t := range strings.Split(tags, ",") {
		if strings.TrimSpace(t) == want {
			return true
		}
	}
	return false
}

// --- jobs ---

func (s *fleetStore) createJob(j Job) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO fleet_jobs (argv, selector, timeout_sec, created_by, created_at)
		VALUES (?, ?, ?, ?, ?)`, j.Argv, j.Selector, j.TimeoutSec, j.CreatedBy, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *fleetStore) getJob(id int64) (Job, error) {
	row := s.db.QueryRow(`SELECT id, argv, selector, timeout_sec, created_by, created_at
		FROM fleet_jobs WHERE id = ?`, id)
	var j Job
	var createdBy sql.NullInt64
	err := row.Scan(&j.ID, &j.Argv, &j.Selector, &j.TimeoutSec, &createdBy, &j.CreatedAt)
	if err != nil {
		return Job{}, err
	}
	if createdBy.Valid {
		j.CreatedBy = &createdBy.Int64
	}
	return j, nil
}

// initResult 为目标节点建一条 pending 结果。
func (s *fleetStore) initResult(jobID int64, nodeID string) error {
	_, err := s.db.Exec(`INSERT INTO fleet_job_results (job_id, node_id, status)
		VALUES (?, ?, ?)`, jobID, nodeID, resultPending)
	return err
}

func (s *fleetStore) setResult(r JobResult) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`UPDATE fleet_job_results
		SET status = ?, exit_code = ?, output = ?, duration_ms = ?, finished_at = ?
		WHERE job_id = ? AND node_id = ?`,
		r.Status, r.ExitCode, r.Output, r.DurationMs, now, r.JobID, r.NodeID)
	return err
}

// markPendingAsTimeout 把任务里仍 pending/running 的结果置为 timeout(收齐截止后调用)。
func (s *fleetStore) markPendingAsTimeout(jobID int64) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`UPDATE fleet_job_results SET status = ?, finished_at = ?
		WHERE job_id = ? AND status IN (?, ?)`,
		resultTimeout, now, jobID, resultPending, resultRunning)
	return err
}

func (s *fleetStore) listResults(jobID int64) ([]JobResult, error) {
	rows, err := s.db.Query(`SELECT job_id, node_id, status, exit_code, output, duration_ms, finished_at
		FROM fleet_job_results WHERE job_id = ? ORDER BY node_id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JobResult{}
	for rows.Next() {
		var r JobResult
		var finished sql.NullInt64
		if err := rows.Scan(&r.JobID, &r.NodeID, &r.Status, &r.ExitCode, &r.Output, &r.DurationMs, &finished); err != nil {
			return nil, err
		}
		if finished.Valid {
			r.FinishedAt = &finished.Int64
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func scanNode(s scanner) (Node, error) {
	var n Node
	err := s.Scan(&n.ID, &n.Name, &n.Tags, &n.Version, &n.Status, &n.LastSeen, &n.EnrolledAt)
	return n, err
}

type scanner interface {
	Scan(dest ...any) error
}
