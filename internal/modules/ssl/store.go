package ssl

import (
	"database/sql"
	"strings"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// sslStore 是本模块私有的 DB 辅助:自建证书记录表 + 设置表,均幂等建表,不动中央 migrations。
type sslStore struct{ db *sql.DB }

// Cert 是一条证书记录。私钥内容绝不入库;仅记录其落盘路径。
type Cert struct {
	ID          int64  `json:"id"`
	Domains     string `json:"domains"`    // 逗号分隔,Domains[0] 为主域名
	Issuer      string `json:"issuer"`     // letsencrypt / uploaded 等
	Challenge   string `json:"challenge"`  // webroot / standalone / dns / upload
	CertPath    string `json:"cert_path"`  // 全链证书路径
	KeyPath     string `json:"key_path"`   // 私钥路径(文件 0600)
	NotAfter    int64  `json:"not_after"`  // 到期 Unix 秒,0 表示未知
	AutoRenew   bool   `json:"auto_renew"` // 是否自动续期
	CreatedBy   *int64 `json:"created_by"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
	LastRenewAt *int64 `json:"last_renew_at"`
}

const createCertTable = `CREATE TABLE IF NOT EXISTS ssl_certs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	domains       TEXT NOT NULL,
	issuer        TEXT NOT NULL DEFAULT '',
	challenge     TEXT NOT NULL DEFAULT '',
	cert_path     TEXT NOT NULL,
	key_path      TEXT NOT NULL,
	not_after     INTEGER NOT NULL DEFAULT 0,
	auto_renew    INTEGER NOT NULL DEFAULT 1,
	created_by    INTEGER,
	created_at    INTEGER NOT NULL,
	updated_at    INTEGER NOT NULL,
	last_renew_at INTEGER
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS ssl_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

func newSSLStore(st *store.Store) (*sslStore, error) {
	if _, err := st.DB.Exec(createCertTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &sslStore{db: st.DB}, nil
}

func (s *sslStore) list() ([]Cert, error) {
	rows, err := s.db.Query(`SELECT id, domains, issuer, challenge, cert_path, key_path,
		not_after, auto_renew, created_by, created_at, updated_at, last_renew_at
		FROM ssl_certs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Cert
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *sslStore) get(id int64) (Cert, error) {
	row := s.db.QueryRow(`SELECT id, domains, issuer, challenge, cert_path, key_path,
		not_after, auto_renew, created_by, created_at, updated_at, last_renew_at
		FROM ssl_certs WHERE id = ?`, id)
	return scanCert(row)
}

func (s *sslStore) create(c Cert) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.Exec(`INSERT INTO ssl_certs
		(domains, issuer, challenge, cert_path, key_path, not_after, auto_renew, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.Domains, c.Issuer, c.Challenge, c.CertPath, c.KeyPath,
		c.NotAfter, boolToInt(c.AutoRenew), c.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *sslStore) setAutoRenew(id int64, on bool) error {
	_, err := s.db.Exec(`UPDATE ssl_certs SET auto_renew = ?, updated_at = ? WHERE id = ?`,
		boolToInt(on), time.Now().Unix(), id)
	return err
}

// markRenewed 记录一次续期:刷新到期时间与上次续期戳。
func (s *sslStore) markRenewed(id int64, notAfter int64) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(`UPDATE ssl_certs SET not_after = ?, last_renew_at = ?, updated_at = ? WHERE id = ?`,
		notAfter, now, now, id)
	return err
}

func (s *sslStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM ssl_certs WHERE id = ?`, id)
	return err
}

// autoRenewable 返回开启自动续期且在 cutoff 前到期(not_after>0)的证书。
func (s *sslStore) autoRenewable(cutoff int64) ([]Cert, error) {
	all, err := s.list()
	if err != nil {
		return nil, err
	}
	var due []Cert
	for _, c := range all {
		if c.AutoRenew && c.NotAfter > 0 && c.NotAfter <= cutoff {
			due = append(due, c)
		}
	}
	return due, nil
}

func (s *sslStore) getSetting(key, def string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM ssl_settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return def, nil
	}
	if err != nil {
		return def, err
	}
	return v, nil
}

func (s *sslStore) setSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO ssl_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanCert(sc scanner) (Cert, error) {
	var c Cert
	var auto int
	var createdBy, lastRenew sql.NullInt64
	err := sc.Scan(&c.ID, &c.Domains, &c.Issuer, &c.Challenge, &c.CertPath, &c.KeyPath,
		&c.NotAfter, &auto, &createdBy, &c.CreatedAt, &c.UpdatedAt, &lastRenew)
	if err != nil {
		return Cert{}, err
	}
	c.AutoRenew = auto != 0
	if createdBy.Valid {
		c.CreatedBy = &createdBy.Int64
	}
	if lastRenew.Valid {
		c.LastRenewAt = &lastRenew.Int64
	}
	return c, nil
}

// domainList 把逗号分隔的 domains 拆为切片(去空白)。
func domainList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
