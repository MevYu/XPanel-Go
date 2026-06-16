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

// Site 是一条站点元数据 + 全部 aaPanel 级结构化设置。
// Config 为已渲染的 nginx 配置文本;Domains 为兼容字段(纯域名列表,由 DomainBindings 派生)。
type Site struct {
	ID             int64        `json:"id"`
	Name           string       `json:"name"`
	Domains        []string     `json:"domains"`
	DomainBindings []Domain     `json:"domain_bindings"`
	Kind           string       `json:"kind"` // type: static | php | proxy
	Listen         int          `json:"listen"`
	RootDir        string       `json:"root_dir"`
	PHPVersion     string       `json:"php_version"`
	IndexDocs      []string     `json:"index_docs"`
	Enabled        bool         `json:"enabled"`
	SSL            SSL          `json:"ssl"`
	RewriteRules   string       `json:"rewrite_rules"`
	ProxyTarget    string       `json:"proxy_target"`
	Proxy          ProxyConfig  `json:"proxy"`
	Limits         Limits       `json:"limits"`
	DirProtect     []DirProtect `json:"dir_protect"`
	Redirects      []Redirect   `json:"redirects"`
	AntiLeech      AntiLeech    `json:"anti_leech"`
	AccessLog      string       `json:"access_log"`
	ErrorLog       string       `json:"error_log"`
	CustomConfig   string       `json:"custom_config"`
	Config         string       `json:"config"`
	CreatedBy      *int64       `json:"created_by"`
	CreatedAt      int64        `json:"created_at"`
	UpdatedAt      int64        `json:"updated_at"`
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
	if err := migrateSites(st.DB); err != nil {
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

// siteCols 是 SELECT/scan 共用的全列清单。
const siteCols = `id, name, domains, kind, listen, enabled, config, created_by, created_at, updated_at,
	root_dir, php_version, index_docs, ssl, rewrite_rules, proxy_target, dir_protect, redirects,
	anti_leech, access_log, error_log, custom_config, domain_bindings, proxy_config, limits`

func (s *siteStore) list() ([]Site, error) {
	rows, err := s.db.Query(`SELECT ` + siteCols + ` FROM sites ORDER BY id`)
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
	row := s.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE id = ?`, id)
	return scanSite(row)
}

func (s *siteStore) getByName(name string) (Site, error) {
	row := s.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE name = ?`, name)
	return scanSite(row)
}

func (s *siteStore) create(st Site) (int64, error) {
	now := time.Now().Unix()
	j := st.jsonFields()
	res, err := s.db.Exec(`INSERT INTO sites
		(name, domains, kind, listen, enabled, config, created_by, created_at, updated_at,
		 root_dir, php_version, index_docs, ssl, rewrite_rules, proxy_target, dir_protect, redirects,
		 anti_leech, access_log, error_log, custom_config, domain_bindings, proxy_config, limits)
		VALUES (?,?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?,?, ?,?,?,?,?,?,?)`,
		st.Name, j.domains, st.Kind, st.Listen, boolToInt(st.Enabled), st.Config, st.CreatedBy, now, now,
		st.RootDir, st.PHPVersion, j.indexDocs, j.ssl, st.RewriteRules, st.ProxyTarget, j.dirProtect, j.redirects,
		j.antiLeech, st.AccessLog, st.ErrorLog, st.CustomConfig, j.domainBindings, j.proxyConfig, j.limits)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// update 持久化一条站点的全部可变字段(不含 name/created_*),并刷新 updated_at。
func (s *siteStore) update(st Site) error {
	j := st.jsonFields()
	_, err := s.db.Exec(`UPDATE sites SET
		domains=?, kind=?, listen=?, enabled=?, config=?, updated_at=?,
		root_dir=?, php_version=?, index_docs=?, ssl=?, rewrite_rules=?, proxy_target=?,
		dir_protect=?, redirects=?, anti_leech=?, access_log=?, error_log=?, custom_config=?, domain_bindings=?, proxy_config=?, limits=?
		WHERE id=?`,
		j.domains, st.Kind, st.Listen, boolToInt(st.Enabled), st.Config, time.Now().Unix(),
		st.RootDir, st.PHPVersion, j.indexDocs, j.ssl, st.RewriteRules, st.ProxyTarget,
		j.dirProtect, j.redirects, j.antiLeech, st.AccessLog, st.ErrorLog, st.CustomConfig, j.domainBindings, j.proxyConfig, j.limits, st.ID)
	return err
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
	var createdBy sql.NullInt64
	var domainsJSON, indexDocsJSON, sslJSON, dirProtectJSON, redirectsJSON, antiLeechJSON, bindingsJSON, proxyJSON, limitsJSON string
	err := sc.Scan(&st.ID, &st.Name, &domainsJSON, &st.Kind, &st.Listen, &enabled,
		&st.Config, &createdBy, &st.CreatedAt, &st.UpdatedAt,
		&st.RootDir, &st.PHPVersion, &indexDocsJSON, &sslJSON, &st.RewriteRules, &st.ProxyTarget,
		&dirProtectJSON, &redirectsJSON, &antiLeechJSON, &st.AccessLog, &st.ErrorLog, &st.CustomConfig, &bindingsJSON, &proxyJSON, &limitsJSON)
	if err != nil {
		return Site{}, err
	}
	st.Enabled = enabled != 0
	if createdBy.Valid {
		st.CreatedBy = &createdBy.Int64
	}
	for _, u := range []struct {
		raw string
		dst any
	}{
		{domainsJSON, &st.Domains},
		{indexDocsJSON, &st.IndexDocs},
		{sslJSON, &st.SSL},
		{dirProtectJSON, &st.DirProtect},
		{redirectsJSON, &st.Redirects},
		{antiLeechJSON, &st.AntiLeech},
		{bindingsJSON, &st.DomainBindings},
		{proxyJSON, &st.Proxy},
		{limitsJSON, &st.Limits},
	} {
		if u.raw == "" {
			continue
		}
		if err := json.Unmarshal([]byte(u.raw), u.dst); err != nil {
			return Site{}, err
		}
	}
	return st, nil
}

// siteJSON 是一条站点 JSON 列的序列化结果。
type siteJSON struct {
	domains, indexDocs, ssl, dirProtect, redirects, antiLeech, domainBindings, proxyConfig, limits string
}

func (st Site) jsonFields() siteJSON {
	return siteJSON{
		domains:        mustJSON(st.Domains),
		indexDocs:      mustJSON(st.IndexDocs),
		ssl:            mustJSON(st.SSL),
		dirProtect:     mustJSON(st.DirProtect),
		redirects:      mustJSON(st.Redirects),
		antiLeech:      mustJSON(st.AntiLeech),
		domainBindings: mustJSON(st.DomainBindings),
		proxyConfig:    mustJSON(st.Proxy),
		limits:         mustJSON(st.Limits),
	}
}

// mustJSON 序列化;切片 nil 归一为 [] 便于列默认值与回显一致。错误仅在不可序列化类型时发生(不会)。
func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "null"
	}
	return string(b)
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
