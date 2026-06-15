package backup

import (
	"database/sql"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// 默认本地备份目录(对标 aaPanel 的 /www/backup)。可在 settings 覆盖。
const defaultBackupDir = "/www/backup"

// schema 幂等建表:三张表。凭证列存 AES-GCM 密文(base64)。
const schema = `
CREATE TABLE IF NOT EXISTS backup_settings (
	id           INTEGER PRIMARY KEY CHECK (id = 1),
	backup_dir   TEXT NOT NULL DEFAULT '',
	mysqldump    TEXT NOT NULL DEFAULT '',
	pgdump       TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS backup_remotes (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	type        TEXT NOT NULL,
	bucket      TEXT NOT NULL DEFAULT '',
	endpoint    TEXT NOT NULL DEFAULT '',
	region      TEXT NOT NULL DEFAULT '',
	access_key  TEXT NOT NULL DEFAULT '',
	secret_enc  TEXT NOT NULL DEFAULT '',
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS backup_jobs (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL,
	target_kind TEXT NOT NULL,
	target      TEXT NOT NULL,
	remote_id   INTEGER,
	frequency   TEXT NOT NULL DEFAULT '',
	keep        INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS backup_records (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	job_id      INTEGER,
	target_kind TEXT NOT NULL,
	target      TEXT NOT NULL,
	filename    TEXT NOT NULL,
	location    TEXT NOT NULL,
	remote_id   INTEGER,
	size        INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL
);`

// Settings 是本模块可配置项。空值回落默认。
type Settings struct {
	BackupDir string `json:"backup_dir"` // 本地备份目录,默认 /www/backup
	MysqlDump string `json:"mysqldump"`  // mysqldump 可执行路径,默认 "mysqldump"
	PgDump    string `json:"pgdump"`     // pg_dump 可执行路径,默认 "pg_dump"
}

func defaultSettings() Settings {
	return Settings{BackupDir: defaultBackupDir, MysqlDump: "mysqldump", PgDump: "pg_dump"}
}

// Remote 是一个 rclone 远端配置。Secret 仅写入用;读出时一律为空(密文不回传)。
type Remote struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"`     // rclone remote 名(也作目录名,白名单校验)
	Type      string `json:"type"`     // rclone 后端类型:s3 / oss / b2 ...
	Bucket    string `json:"bucket"`   // 桶名
	Endpoint  string `json:"endpoint"` // 自定义 endpoint(OSS/MinIO 等)
	Region    string `json:"region"`   //
	AccessKey string `json:"access_key"`
	Secret    string `json:"secret,omitempty"` // 写入用,落库前加密;读出恒为空
	SecretSet bool   `json:"secret_set"`       // 是否已配置密钥(供前端展示)
	CreatedAt int64  `json:"created_at"`
}

// Job 是备份策略元数据(频率/保留份数)。实际定时由 cron/后台触发。
type Job struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	TargetKind string `json:"target_kind"` // "path" | "mysql" | "postgres"
	Target     string `json:"target"`      // 目录/文件路径,或数据库名
	RemoteID   *int64 `json:"remote_id"`   // 非空则备份后上传到该远端
	Frequency  string `json:"frequency"`   // 自由文本(如 "daily" / cron 表达式)
	Keep       int    `json:"keep"`        // 保留份数,0 表示不清理
	CreatedAt  int64  `json:"created_at"`
}

// Record 是一次备份的结果记录。
type Record struct {
	ID         int64  `json:"id"`
	JobID      *int64 `json:"job_id"`
	TargetKind string `json:"target_kind"`
	Target     string `json:"target"`
	Filename   string `json:"filename"`
	Location   string `json:"location"` // "local" | "remote"
	RemoteID   *int64 `json:"remote_id"`
	Size       int64  `json:"size"`
	CreatedAt  int64  `json:"created_at"`
}

// backupStore 读写四张表,远端 secret 列加解密。
type backupStore struct {
	db   *sql.DB
	cryp *cryptor
}

func newBackupStore(st *store.Store, cryp *cryptor) (*backupStore, error) {
	if _, err := st.DB.Exec(schema); err != nil {
		return nil, err
	}
	return &backupStore{db: st.DB, cryp: cryp}, nil
}

// --- settings ---

func (s *backupStore) settings() (Settings, error) {
	cur := defaultSettings()
	var got Settings
	row := s.db.QueryRow(`SELECT backup_dir, mysqldump, pgdump FROM backup_settings WHERE id = 1`)
	err := row.Scan(&got.BackupDir, &got.MysqlDump, &got.PgDump)
	if errors.Is(err, sql.ErrNoRows) {
		return cur, nil
	}
	if err != nil {
		return Settings{}, err
	}
	if got.BackupDir != "" {
		cur.BackupDir = got.BackupDir
	}
	if got.MysqlDump != "" {
		cur.MysqlDump = got.MysqlDump
	}
	if got.PgDump != "" {
		cur.PgDump = got.PgDump
	}
	return cur, nil
}

func (s *backupStore) saveSettings(in Settings) error {
	_, err := s.db.Exec(`INSERT INTO backup_settings (id, backup_dir, mysqldump, pgdump)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 backup_dir=excluded.backup_dir, mysqldump=excluded.mysqldump, pgdump=excluded.pgdump`,
		in.BackupDir, in.MysqlDump, in.PgDump)
	return err
}

// --- remotes ---

// addRemote 加密 secret 后落库,返回带 ID 的 remote(secret 已清空)。
func (s *backupStore) addRemote(r Remote) (Remote, error) {
	enc, err := s.cryp.encrypt(r.Secret)
	if err != nil {
		return Remote{}, err
	}
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO backup_remotes
		(name, type, bucket, endpoint, region, access_key, secret_enc, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.Name, r.Type, r.Bucket, r.Endpoint, r.Region, r.AccessKey, enc, now)
	if err != nil {
		return Remote{}, err
	}
	id, _ := res.LastInsertId()
	r.ID, r.CreatedAt = id, now
	r.SecretSet = r.Secret != ""
	r.Secret = ""
	return r, nil
}

// listRemotes 返回所有远端,secret 一律屏蔽(secret_set 标示是否已配置)。
func (s *backupStore) listRemotes() ([]Remote, error) {
	rows, err := s.db.Query(`SELECT id, name, type, bucket, endpoint, region, access_key, secret_enc, created_at
		FROM backup_remotes ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Remote{}
	for rows.Next() {
		var r Remote
		var enc string
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Bucket, &r.Endpoint, &r.Region, &r.AccessKey, &enc, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.SecretSet = enc != ""
		out = append(out, r)
	}
	return out, rows.Err()
}

// getRemote 取单个远端并解密 secret(供内部建 rclone 连接用,不对外输出)。
func (s *backupStore) getRemote(id int64) (Remote, error) {
	var r Remote
	var enc string
	row := s.db.QueryRow(`SELECT id, name, type, bucket, endpoint, region, access_key, secret_enc, created_at
		FROM backup_remotes WHERE id = ?`, id)
	err := row.Scan(&r.ID, &r.Name, &r.Type, &r.Bucket, &r.Endpoint, &r.Region, &r.AccessKey, &enc, &r.CreatedAt)
	if err != nil {
		return Remote{}, err
	}
	plain, err := s.cryp.decrypt(enc)
	if err != nil {
		return Remote{}, err
	}
	r.Secret = plain
	r.SecretSet = enc != ""
	return r, nil
}

func (s *backupStore) deleteRemote(id int64) error {
	_, err := s.db.Exec(`DELETE FROM backup_remotes WHERE id = ?`, id)
	return err
}

// --- jobs ---

func (s *backupStore) addJob(j Job) (Job, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO backup_jobs
		(name, target_kind, target, remote_id, frequency, keep, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)`,
		j.Name, j.TargetKind, j.Target, j.RemoteID, j.Frequency, j.Keep, now)
	if err != nil {
		return Job{}, err
	}
	id, _ := res.LastInsertId()
	j.ID, j.CreatedAt = id, now
	return j, nil
}

func (s *backupStore) listJobs() ([]Job, error) {
	rows, err := s.db.Query(`SELECT id, name, target_kind, target, remote_id, frequency, keep, created_at
		FROM backup_jobs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Name, &j.TargetKind, &j.Target, &j.RemoteID, &j.Frequency, &j.Keep, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *backupStore) getJob(id int64) (Job, error) {
	var j Job
	row := s.db.QueryRow(`SELECT id, name, target_kind, target, remote_id, frequency, keep, created_at
		FROM backup_jobs WHERE id = ?`, id)
	err := row.Scan(&j.ID, &j.Name, &j.TargetKind, &j.Target, &j.RemoteID, &j.Frequency, &j.Keep, &j.CreatedAt)
	return j, err
}

func (s *backupStore) deleteJob(id int64) error {
	_, err := s.db.Exec(`DELETE FROM backup_jobs WHERE id = ?`, id)
	return err
}

// --- records ---

func (s *backupStore) addRecord(rec Record) (Record, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO backup_records
		(job_id, target_kind, target, filename, location, remote_id, size, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.JobID, rec.TargetKind, rec.Target, rec.Filename, rec.Location, rec.RemoteID, rec.Size, now)
	if err != nil {
		return Record{}, err
	}
	id, _ := res.LastInsertId()
	rec.ID, rec.CreatedAt = id, now
	return rec, nil
}

// listRecords 返回最近备份记录,可按 job 过滤(jobID==nil 表示全部)。
func (s *backupStore) listRecords(jobID *int64) ([]Record, error) {
	var rows *sql.Rows
	var err error
	if jobID != nil {
		rows, err = s.db.Query(`SELECT id, job_id, target_kind, target, filename, location, remote_id, size, created_at
			FROM backup_records WHERE job_id = ? ORDER BY id DESC`, *jobID)
	} else {
		rows, err = s.db.Query(`SELECT id, job_id, target_kind, target, filename, location, remote_id, size, created_at
			FROM backup_records ORDER BY id DESC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.JobID, &r.TargetKind, &r.Target, &r.Filename, &r.Location, &r.RemoteID, &r.Size, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *backupStore) getRecord(id int64) (Record, error) {
	var r Record
	row := s.db.QueryRow(`SELECT id, job_id, target_kind, target, filename, location, remote_id, size, created_at
		FROM backup_records WHERE id = ?`, id)
	err := row.Scan(&r.ID, &r.JobID, &r.TargetKind, &r.Target, &r.Filename, &r.Location, &r.RemoteID, &r.Size, &r.CreatedAt)
	return r, err
}

func (s *backupStore) deleteRecord(id int64) error {
	_, err := s.db.Exec(`DELETE FROM backup_records WHERE id = ?`, id)
	return err
}

// staleLocalRecords 返回某 job 超出保留份数 keep 的本地备份记录(最旧的在前),
// 供清理:删文件 + 删记录。keep<=0 时返回空(不清理)。
func (s *backupStore) staleLocalRecords(jobID int64, keep int) ([]Record, error) {
	if keep <= 0 {
		return nil, nil
	}
	recs, err := s.listRecords(&jobID)
	if err != nil {
		return nil, err
	}
	// recs 已按 created_at DESC(新→旧)。仅本地文件参与保留策略。
	var local []Record
	for _, r := range recs {
		if r.Location == "local" {
			local = append(local, r)
		}
	}
	if len(local) <= keep {
		return nil, nil
	}
	stale := local[keep:]
	// 反转为旧→新,便于调用方按时间顺序删
	for i, j := 0, len(stale)-1; i < j; i, j = i+1, j-1 {
		stale[i], stale[j] = stale[j], stale[i]
	}
	return stale, nil
}
