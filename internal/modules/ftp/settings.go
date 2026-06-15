package ftp

import (
	"database/sql"
	"errors"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Settings 是本模块可配置的路径。覆盖值落库,未设置则用默认值。绝不含口令。
type Settings struct {
	// HomeBase 是虚拟用户家目录的基路径:新建账户的默认家目录为 HomeBase/<user>,
	// 且所有家目录必须落在此子树内(挡路径逃逸)。
	HomeBase string `json:"home_base"`
	// ConfigDir 是 FTP 服务的配置目录(展示/未来扩展用)。
	ConfigDir string `json:"config_dir"`
	// VirtualUID/VirtualGID 是虚拟用户映射到的系统 uid/gid。
	VirtualUID string `json:"virtual_uid"`
	VirtualGID string `json:"virtual_gid"`
}

// defaultSettings 返回各路径的合理默认值(对标 pure-ftpd 常见部署)。
func defaultSettings() Settings {
	return Settings{
		HomeBase:   "/home/ftp",
		ConfigDir:  "/etc/pure-ftpd",
		VirtualUID: "ftpuser",
		VirtualGID: "ftpgroup",
	}
}

// settingsSchema 幂等建表:单行 KV,id 固定为 1。不存口令。
const settingsSchema = `CREATE TABLE IF NOT EXISTS ftp_settings (
	id           INTEGER PRIMARY KEY CHECK (id = 1),
	home_base    TEXT NOT NULL DEFAULT '',
	config_dir   TEXT NOT NULL DEFAULT '',
	virtual_uid  TEXT NOT NULL DEFAULT '',
	virtual_gid  TEXT NOT NULL DEFAULT ''
)`

// accountsSchema 幂等建表:账户元数据(用户名/家目录/只读/启用),绝不含口令。
// 口令由 FTP 后端自己的用户库哈希存储。
const accountsSchema = `CREATE TABLE IF NOT EXISTS ftp_accounts (
	user      TEXT PRIMARY KEY,
	home      TEXT NOT NULL,
	readonly  INTEGER NOT NULL DEFAULT 0,
	enabled   INTEGER NOT NULL DEFAULT 1
)`

// settingsStore 读写 ftp_settings 单行与 ftp_accounts 元数据。
type settingsStore struct{ db *sql.DB }

func newSettingsStore(st *store.Store) (*settingsStore, error) {
	if _, err := st.DB.Exec(settingsSchema); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(accountsSchema); err != nil {
		return nil, err
	}
	return &settingsStore{db: st.DB}, nil
}

// effective 返回有效设置:已落库的覆盖值盖在默认值上。
func (s *settingsStore) effective() (Settings, error) {
	cur := defaultSettings()
	var got Settings
	row := s.db.QueryRow(`SELECT home_base, config_dir, virtual_uid, virtual_gid FROM ftp_settings WHERE id = 1`)
	err := row.Scan(&got.HomeBase, &got.ConfigDir, &got.VirtualUID, &got.VirtualGID)
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
func (s *settingsStore) save(in Settings) error {
	_, err := s.db.Exec(`INSERT INTO ftp_settings (id, home_base, config_dir, virtual_uid, virtual_gid)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 home_base=excluded.home_base, config_dir=excluded.config_dir,
		 virtual_uid=excluded.virtual_uid, virtual_gid=excluded.virtual_gid`,
		in.HomeBase, in.ConfigDir, in.VirtualUID, in.VirtualGID)
	return err
}

// overlay 把 got 中的非空字段盖到 dst(空串视为"未设",用默认)。
func overlay(dst *Settings, got Settings) {
	if got.HomeBase != "" {
		dst.HomeBase = got.HomeBase
	}
	if got.ConfigDir != "" {
		dst.ConfigDir = got.ConfigDir
	}
	if got.VirtualUID != "" {
		dst.VirtualUID = got.VirtualUID
	}
	if got.VirtualGID != "" {
		dst.VirtualGID = got.VirtualGID
	}
}

// acctMeta 是落库的账户元数据(无口令)。
type acctMeta struct {
	User     string `json:"user"`
	Home     string `json:"home"`
	Readonly bool   `json:"readonly"`
	Enabled  bool   `json:"enabled"`
}

// upsertAccount 落库账户元数据(创建/改权限)。
func (s *settingsStore) upsertAccount(m acctMeta) error {
	_, err := s.db.Exec(`INSERT INTO ftp_accounts (user, home, readonly, enabled)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user) DO UPDATE SET home=excluded.home, readonly=excluded.readonly, enabled=excluded.enabled`,
		m.User, m.Home, boolToInt(m.Readonly), boolToInt(m.Enabled))
	return err
}

// deleteAccount 删除账户元数据。
func (s *settingsStore) deleteAccount(user string) error {
	_, err := s.db.Exec(`DELETE FROM ftp_accounts WHERE user = ?`, user)
	return err
}

// setEnabled 更新账户启用状态元数据。
func (s *settingsStore) setEnabled(user string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE ftp_accounts SET enabled = ? WHERE user = ?`, boolToInt(enabled), user)
	return err
}

// listAccounts 返回所有账户元数据(无口令)。
func (s *settingsStore) listAccounts() ([]acctMeta, error) {
	rows, err := s.db.Query(`SELECT user, home, readonly, enabled FROM ftp_accounts ORDER BY user`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []acctMeta
	for rows.Next() {
		var m acctMeta
		var ro, en int
		if err := rows.Scan(&m.User, &m.Home, &ro, &en); err != nil {
			return nil, err
		}
		m.Readonly, m.Enabled = ro != 0, en != 0
		out = append(out, m)
	}
	return out, rows.Err()
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
