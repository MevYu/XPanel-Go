package mail

import (
	"database/sql"
	"errors"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Settings 是本模块可配置的路径/目录。覆盖值落库,未设置则用默认值。绝不含口令。
type Settings struct {
	// PostfixConfigDir 是 postfix 配置目录(虚拟域/别名 map 文件所在,postmap 目标)。
	PostfixConfigDir string `json:"postfix_config_dir"`
	// DovecotConfigDir 是 dovecot 配置目录(虚拟用户库所在)。
	DovecotConfigDir string `json:"dovecot_config_dir"`
	// MailStoreDir 是邮件存储根目录(虚拟邮箱 maildir 的基路径)。
	MailStoreDir string `json:"mail_store_dir"`
	// VirtualMailboxFile 是 postfix virtual_mailbox_maps 源文件路径。
	VirtualMailboxFile string `json:"virtual_mailbox_file"`
	// VirtualDomainFile 是 postfix virtual_mailbox_domains 源文件路径。
	VirtualDomainFile string `json:"virtual_domain_file"`
	// VirtualAliasFile 是 postfix virtual_alias_maps 源文件路径。
	VirtualAliasFile string `json:"virtual_alias_file"`
}

// defaultSettings 返回各路径的合理默认值(对标 postfix/dovecot 虚拟邮箱常见部署)。
func defaultSettings() Settings {
	return Settings{
		PostfixConfigDir:   "/etc/postfix",
		DovecotConfigDir:   "/etc/dovecot",
		MailStoreDir:       "/var/vmail",
		VirtualMailboxFile: "/etc/postfix/vmailbox",
		VirtualDomainFile:  "/etc/postfix/virtual_domains",
		VirtualAliasFile:   "/etc/postfix/virtual",
	}
}

// settingsSchema 幂等建表:单行 KV,id 固定为 1。不存口令。
const settingsSchema = `CREATE TABLE IF NOT EXISTS mail_settings (
	id                   INTEGER PRIMARY KEY CHECK (id = 1),
	postfix_config_dir   TEXT NOT NULL DEFAULT '',
	dovecot_config_dir   TEXT NOT NULL DEFAULT '',
	mail_store_dir       TEXT NOT NULL DEFAULT '',
	virtual_mailbox_file TEXT NOT NULL DEFAULT '',
	virtual_domain_file  TEXT NOT NULL DEFAULT '',
	virtual_alias_file   TEXT NOT NULL DEFAULT ''
)`

// domainsSchema 幂等建表:邮件域。
const domainsSchema = `CREATE TABLE IF NOT EXISTS mail_domains (
	domain  TEXT PRIMARY KEY,
	enabled INTEGER NOT NULL DEFAULT 1
)`

// mailboxesSchema 幂等建表:邮箱元数据(地址/maildir/配额),绝不含口令。
// 口令由 dovecot 用户库哈希存储(doveadm pw),XPanel 的库只留 maildir 路径与配额。
const mailboxesSchema = `CREATE TABLE IF NOT EXISTS mail_mailboxes (
	address  TEXT PRIMARY KEY,
	domain   TEXT NOT NULL,
	maildir  TEXT NOT NULL,
	quota_mb INTEGER NOT NULL DEFAULT 0
)`

// aliasesSchema 幂等建表:别名/转发(source -> destination)。
// 同一 source 可转发到多个 destination,故复合主键。
const aliasesSchema = `CREATE TABLE IF NOT EXISTS mail_aliases (
	source      TEXT NOT NULL,
	destination TEXT NOT NULL,
	PRIMARY KEY (source, destination)
)`

// dataStore 读写 mail_* 各表。
type dataStore struct{ db *sql.DB }

func newDataStore(st *store.Store) (*dataStore, error) {
	for _, schema := range []string{settingsSchema, domainsSchema, mailboxesSchema, aliasesSchema} {
		if _, err := st.DB.Exec(schema); err != nil {
			return nil, err
		}
	}
	return &dataStore{db: st.DB}, nil
}

// effective 返回有效设置:已落库的覆盖值盖在默认值上。
func (s *dataStore) effective() (Settings, error) {
	cur := defaultSettings()
	var got Settings
	row := s.db.QueryRow(`SELECT postfix_config_dir, dovecot_config_dir, mail_store_dir,
		virtual_mailbox_file, virtual_domain_file, virtual_alias_file FROM mail_settings WHERE id = 1`)
	err := row.Scan(&got.PostfixConfigDir, &got.DovecotConfigDir, &got.MailStoreDir,
		&got.VirtualMailboxFile, &got.VirtualDomainFile, &got.VirtualAliasFile)
	if errors.Is(err, sql.ErrNoRows) {
		return cur, nil
	}
	if err != nil {
		return Settings{}, err
	}
	overlay(&cur, got)
	return cur, nil
}

// save 覆盖单行设置(空字段保留默认,经 effective overlay 体现)。
func (s *dataStore) save(in Settings) error {
	_, err := s.db.Exec(`INSERT INTO mail_settings (id, postfix_config_dir, dovecot_config_dir,
		mail_store_dir, virtual_mailbox_file, virtual_domain_file, virtual_alias_file)
		VALUES (1, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 postfix_config_dir=excluded.postfix_config_dir, dovecot_config_dir=excluded.dovecot_config_dir,
		 mail_store_dir=excluded.mail_store_dir, virtual_mailbox_file=excluded.virtual_mailbox_file,
		 virtual_domain_file=excluded.virtual_domain_file, virtual_alias_file=excluded.virtual_alias_file`,
		in.PostfixConfigDir, in.DovecotConfigDir, in.MailStoreDir,
		in.VirtualMailboxFile, in.VirtualDomainFile, in.VirtualAliasFile)
	return err
}

// overlay 把 got 中的非空字段盖到 dst(空串视为"未设",用默认)。
func overlay(dst *Settings, got Settings) {
	for _, f := range []struct {
		got string
		dst *string
	}{
		{got.PostfixConfigDir, &dst.PostfixConfigDir},
		{got.DovecotConfigDir, &dst.DovecotConfigDir},
		{got.MailStoreDir, &dst.MailStoreDir},
		{got.VirtualMailboxFile, &dst.VirtualMailboxFile},
		{got.VirtualDomainFile, &dst.VirtualDomainFile},
		{got.VirtualAliasFile, &dst.VirtualAliasFile},
	} {
		if f.got != "" {
			*f.dst = f.got
		}
	}
}

// --- 邮件域 ---

func (s *dataStore) addDomain(domain string) error {
	_, err := s.db.Exec(`INSERT INTO mail_domains (domain, enabled) VALUES (?, 1)
		ON CONFLICT(domain) DO NOTHING`, domain)
	return err
}

func (s *dataStore) deleteDomain(domain string) error {
	_, err := s.db.Exec(`DELETE FROM mail_domains WHERE domain = ?`, domain)
	return err
}

func (s *dataStore) hasDomain(domain string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM mail_domains WHERE domain = ?`, domain).Scan(&n)
	return n > 0, err
}

func (s *dataStore) listDomains() ([]domainMeta, error) {
	rows, err := s.db.Query(`SELECT domain, enabled FROM mail_domains ORDER BY domain`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domainMeta
	for rows.Next() {
		var m domainMeta
		var en int
		if err := rows.Scan(&m.Domain, &en); err != nil {
			return nil, err
		}
		m.Enabled = en != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- 邮箱 ---

func (s *dataStore) upsertMailbox(m mailboxMeta) error {
	_, err := s.db.Exec(`INSERT INTO mail_mailboxes (address, domain, maildir, quota_mb)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(address) DO UPDATE SET domain=excluded.domain, maildir=excluded.maildir, quota_mb=excluded.quota_mb`,
		m.Address, m.Domain, m.Maildir, m.QuotaMB)
	return err
}

func (s *dataStore) deleteMailbox(address string) error {
	_, err := s.db.Exec(`DELETE FROM mail_mailboxes WHERE address = ?`, address)
	return err
}

func (s *dataStore) listMailboxes() ([]mailboxMeta, error) {
	rows, err := s.db.Query(`SELECT address, domain, maildir, quota_mb FROM mail_mailboxes ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []mailboxMeta
	for rows.Next() {
		var m mailboxMeta
		if err := rows.Scan(&m.Address, &m.Domain, &m.Maildir, &m.QuotaMB); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// --- 别名 ---

func (s *dataStore) addAlias(source, destination string) error {
	_, err := s.db.Exec(`INSERT INTO mail_aliases (source, destination) VALUES (?, ?)
		ON CONFLICT(source, destination) DO NOTHING`, source, destination)
	return err
}

func (s *dataStore) deleteAlias(source, destination string) error {
	_, err := s.db.Exec(`DELETE FROM mail_aliases WHERE source = ? AND destination = ?`, source, destination)
	return err
}

func (s *dataStore) listAliases() ([]aliasMeta, error) {
	rows, err := s.db.Query(`SELECT source, destination FROM mail_aliases ORDER BY source, destination`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []aliasMeta
	for rows.Next() {
		var a aliasMeta
		if err := rows.Scan(&a.Source, &a.Destination); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// domainMeta 是落库的邮件域元数据。
type domainMeta struct {
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
}

// mailboxMeta 是落库的邮箱元数据(无口令)。
type mailboxMeta struct {
	Address string `json:"address"`
	Domain  string `json:"domain"`
	Maildir string `json:"maildir"`
	QuotaMB int64  `json:"quota_mb"`
}

// aliasMeta 是落库的别名/转发元数据。
type aliasMeta struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
}
