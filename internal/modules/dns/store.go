package dns

import (
	"database/sql"
	"errors"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// dnsStore 是本模块私有 DB 辅助:自建域名/记录表 + 设置表,幂等建表,不动中央 migrations。
type dnsStore struct {
	db   *sql.DB
	cryp *cryptor
}

// Domain 是一个受管 zone。
type Domain struct {
	ID        int64  `json:"id"`
	Name      string `json:"name"` // zone 域名,小写规范化
	CreatedAt int64  `json:"created_at"`
}

const createDomainsTable = `CREATE TABLE IF NOT EXISTS dns_domains (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	name       TEXT NOT NULL UNIQUE,
	created_at INTEGER NOT NULL
)`

const createRecordsTable = `CREATE TABLE IF NOT EXISTS dns_records (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	domain_id  INTEGER NOT NULL REFERENCES dns_domains(id) ON DELETE CASCADE,
	name       TEXT NOT NULL,
	type       TEXT NOT NULL,
	value      TEXT NOT NULL,
	ttl        INTEGER NOT NULL DEFAULT 3600,
	priority   INTEGER NOT NULL DEFAULT 0
)`

// dns_settings 单行 KV(id=1)。provider 凭证列存 AES-GCM 密文(base64),其余明文。
const createSettingsTable = `CREATE TABLE IF NOT EXISTS dns_settings (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	provider_kind   TEXT NOT NULL DEFAULT 'bind',
	provider_creds  TEXT NOT NULL DEFAULT '',
	bind_zone_dir   TEXT NOT NULL DEFAULT ''
)`

func newDNSStore(st *store.Store, cryp *cryptor) (*dnsStore, error) {
	for _, ddl := range []string{createDomainsTable, createRecordsTable, createSettingsTable} {
		if _, err := st.DB.Exec(ddl); err != nil {
			return nil, err
		}
	}
	return &dnsStore{db: st.DB, cryp: cryp}, nil
}

// --- domains ---

func (s *dnsStore) listDomains() ([]Domain, error) {
	rows, err := s.db.Query(`SELECT id, name, created_at FROM dns_domains ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.Name, &d.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

func (s *dnsStore) getDomain(id int64) (Domain, error) {
	var d Domain
	err := s.db.QueryRow(`SELECT id, name, created_at FROM dns_domains WHERE id = ?`, id).
		Scan(&d.ID, &d.Name, &d.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Domain{}, errNotFound
	}
	return d, err
}

func (s *dnsStore) createDomain(name string, now int64) (Domain, error) {
	res, err := s.db.Exec(`INSERT INTO dns_domains (name, created_at) VALUES (?, ?)`, name, now)
	if err != nil {
		return Domain{}, err
	}
	id, _ := res.LastInsertId()
	return Domain{ID: id, Name: name, CreatedAt: now}, nil
}

func (s *dnsStore) deleteDomain(id int64) error {
	res, err := s.db.Exec(`DELETE FROM dns_domains WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// --- records ---

func (s *dnsStore) listRecords(domainID int64) ([]Record, error) {
	rows, err := s.db.Query(`SELECT id, name, type, value, ttl, priority
		FROM dns_records WHERE domain_id = ? ORDER BY id`, domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.ID, &r.Name, &r.Type, &r.Value, &r.TTL, &r.Priority); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *dnsStore) createRecord(domainID int64, r Record) (Record, error) {
	res, err := s.db.Exec(`INSERT INTO dns_records (domain_id, name, type, value, ttl, priority)
		VALUES (?, ?, ?, ?, ?, ?)`, domainID, r.Name, r.Type, r.Value, r.TTL, r.Priority)
	if err != nil {
		return Record{}, err
	}
	r.ID, _ = res.LastInsertId()
	return r, nil
}

// updateRecord 更新一条记录(限定 domainID 防越权改他域记录)。
func (s *dnsStore) updateRecord(domainID, id int64, r Record) error {
	res, err := s.db.Exec(`UPDATE dns_records SET name=?, type=?, value=?, ttl=?, priority=?
		WHERE id=? AND domain_id=?`, r.Name, r.Type, r.Value, r.TTL, r.Priority, id, domainID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *dnsStore) deleteRecord(domainID, id int64) error {
	res, err := s.db.Exec(`DELETE FROM dns_records WHERE id=? AND domain_id=?`, id, domainID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

// --- settings ---

// Settings 是模块可配置项:provider 类型、凭证(写入用;读出屏蔽)、bind zone 目录。
type Settings struct {
	ProviderKind  string `json:"provider_kind"`  // bind | mock(示例云 provider)
	ProviderCreds string `json:"provider_creds"` // 云 provider API 凭证;读出时屏蔽为空
	BindZoneDir   string `json:"bind_zone_dir"`  // bind zone 文件目录
}

const defaultBindZoneDir = "/etc/bind/zones"

func defaultSettings() Settings {
	return Settings{ProviderKind: "bind", BindZoneDir: defaultBindZoneDir}
}

// effective 返回有效设置:落库覆盖盖在默认上,凭证解密为明文(供内部建后端用)。
func (s *dnsStore) effective() (Settings, error) {
	cur := defaultSettings()
	var kind, encCreds, zoneDir string
	err := s.db.QueryRow(`SELECT provider_kind, provider_creds, bind_zone_dir
		FROM dns_settings WHERE id = 1`).Scan(&kind, &encCreds, &zoneDir)
	if errors.Is(err, sql.ErrNoRows) {
		return cur, nil
	}
	if err != nil {
		return Settings{}, err
	}
	if kind != "" {
		cur.ProviderKind = kind
	}
	if zoneDir != "" {
		cur.BindZoneDir = zoneDir
	}
	plain, derr := s.cryp.decrypt(encCreds)
	if derr != nil {
		return Settings{}, derr
	}
	cur.ProviderCreds = plain
	return cur, nil
}

// masked 返回有效设置但抹掉凭证(供 GET /settings),credsSet 标示是否已配置凭证。
func (s *dnsStore) masked() (Settings, bool, error) {
	eff, err := s.effective()
	if err != nil {
		return Settings{}, false, err
	}
	credsSet := eff.ProviderCreds != ""
	eff.ProviderCreds = ""
	return eff, credsSet, nil
}

// saveSettings 覆盖单行设置。凭证非空则加密落库;空串保留旧密文(不清空)。
func (s *dnsStore) saveSettings(in Settings) error {
	var prevEnc string
	err := s.db.QueryRow(`SELECT provider_creds FROM dns_settings WHERE id = 1`).Scan(&prevEnc)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	enc := prevEnc
	if in.ProviderCreds != "" {
		enc, err = s.cryp.encrypt(in.ProviderCreds)
		if err != nil {
			return err
		}
	}
	_, err = s.db.Exec(`INSERT INTO dns_settings (id, provider_kind, provider_creds, bind_zone_dir)
		VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  provider_kind=excluded.provider_kind,
		  provider_creds=excluded.provider_creds,
		  bind_zone_dir=excluded.bind_zone_dir`,
		in.ProviderKind, enc, in.BindZoneDir)
	return err
}

var errNotFound = errors.New("not found")
