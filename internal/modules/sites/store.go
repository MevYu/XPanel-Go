package sites

import (
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// siteStore 是本模块私有 DB 辅助:自建表存站点元数据与设置,不动中央 migrations。
type siteStore struct{ db *sql.DB }

// Site 是一条站点元数据。Config 为已渲染的 nginx 配置文本(便于查看/编辑回显)。
type Site struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Domains   []string `json:"domains"`
	Kind      string   `json:"kind"`
	Listen    int      `json:"listen"`
	Enabled   bool     `json:"enabled"`
	Config    string   `json:"config"`
	CreatedBy *int64   `json:"created_by"`
	CreatedAt int64    `json:"created_at"`
	UpdatedAt int64    `json:"updated_at"`
}

const createSitesTable = `CREATE TABLE IF NOT EXISTS sites (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE,
	domains    TEXT NOT NULL,
	kind       TEXT NOT NULL,
	listen     INTEGER NOT NULL DEFAULT 80,
	enabled    INTEGER NOT NULL DEFAULT 1,
	config     TEXT NOT NULL DEFAULT '',
	created_by INTEGER,
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS site_settings (
	id         INTEGER PRIMARY KEY CHECK (id = 1),
	web_root   TEXT NOT NULL,
	conf_dir   TEXT NOT NULL,
	log_dir    TEXT NOT NULL,
	php_socket TEXT NOT NULL
)`

func newSiteStore(st *store.Store) (*siteStore, error) {
	if _, err := st.DB.Exec(createSitesTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &siteStore{db: st.DB}, nil
}

// getSettings 返回持久化设置;无行则返回默认值(不写库,待用户首次 PUT)。
func (s *siteStore) getSettings() (Settings, error) {
	row := s.db.QueryRow(`SELECT web_root, conf_dir, log_dir, php_socket FROM site_settings WHERE id = 1`)
	var set Settings
	err := row.Scan(&set.WebRoot, &set.ConfDir, &set.LogDir, &set.PHPSocket)
	if errors.Is(err, sql.ErrNoRows) {
		return DefaultSettings(), nil
	}
	if err != nil {
		return Settings{}, err
	}
	return set, nil
}

func (s *siteStore) putSettings(set Settings) error {
	_, err := s.db.Exec(`INSERT INTO site_settings (id, web_root, conf_dir, log_dir, php_socket)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET web_root=excluded.web_root, conf_dir=excluded.conf_dir,
			log_dir=excluded.log_dir, php_socket=excluded.php_socket`,
		set.WebRoot, set.ConfDir, set.LogDir, set.PHPSocket)
	return err
}

func (s *siteStore) list() ([]Site, error) {
	rows, err := s.db.Query(`SELECT id, name, domains, kind, listen, enabled, config,
		created_by, created_at, updated_at FROM sites ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Site
	for rows.Next() {
		st, err := scanSite(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

func (s *siteStore) get(id int64) (Site, error) {
	row := s.db.QueryRow(`SELECT id, name, domains, kind, listen, enabled, config,
		created_by, created_at, updated_at FROM sites WHERE id = ?`, id)
	return scanSite(row)
}

func (s *siteStore) getByName(name string) (Site, error) {
	row := s.db.QueryRow(`SELECT id, name, domains, kind, listen, enabled, config,
		created_by, created_at, updated_at FROM sites WHERE name = ?`, name)
	return scanSite(row)
}

func (s *siteStore) create(st Site) (int64, error) {
	now := time.Now().Unix()
	domainsJSON, err := json.Marshal(st.Domains)
	if err != nil {
		return 0, err
	}
	res, err := s.db.Exec(`INSERT INTO sites (name, domains, kind, listen, enabled, config, created_by, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		st.Name, string(domainsJSON), st.Kind, st.Listen, boolToInt(st.Enabled), st.Config, st.CreatedBy, now, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *siteStore) setEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE sites SET enabled = ?, updated_at = ? WHERE id = ?`,
		boolToInt(enabled), time.Now().Unix(), id)
	return err
}

func (s *siteStore) updateConfig(id int64, config string) error {
	_, err := s.db.Exec(`UPDATE sites SET config = ?, updated_at = ? WHERE id = ?`,
		config, time.Now().Unix(), id)
	return err
}

func (s *siteStore) delete(id int64) error {
	_, err := s.db.Exec(`DELETE FROM sites WHERE id = ?`, id)
	return err
}

type scanner interface {
	Scan(dest ...any) error
}

func scanSite(sc scanner) (Site, error) {
	var st Site
	var enabled int
	var domainsJSON string
	var createdBy sql.NullInt64
	err := sc.Scan(&st.ID, &st.Name, &domainsJSON, &st.Kind, &st.Listen, &enabled,
		&st.Config, &createdBy, &st.CreatedAt, &st.UpdatedAt)
	if err != nil {
		return Site{}, err
	}
	st.Enabled = enabled != 0
	if createdBy.Valid {
		st.CreatedBy = &createdBy.Int64
	}
	if err := json.Unmarshal([]byte(domainsJSON), &st.Domains); err != nil {
		return Site{}, err
	}
	return st, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
