package docker

import (
	"database/sql"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// 默认可配置路径。GET/PUT /settings(admin)可覆盖。
const (
	defaultComposeDir = "/opt/xpanel/compose" // compose 项目目录:每个项目一个子目录,内含 compose 文件
	defaultDockerRoot = "/var/lib/docker"     // docker data-root(信息展示用)
)

// Settings 是模块的可配置项,持久化在自建表里。
type Settings struct {
	ComposeDir string `json:"compose_dir"` // compose 项目根目录
	DockerRoot string `json:"docker_root"` // docker 数据根目录
}

// DefaultSettings 返回内置默认值。
func DefaultSettings() Settings {
	return Settings{ComposeDir: defaultComposeDir, DockerRoot: defaultDockerRoot}
}

// dockStore 是本模块私有的 DB 辅助:自建设置表。不动中央 migrations,建表幂等。
type dockStore struct{ db *sql.DB }

const createSettingsTable = `CREATE TABLE IF NOT EXISTS docker_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

// docker_registries 存镜像仓库凭证。password 列存 AES-GCM 密文(base64),绝不明文。
const createRegistriesTable = `CREATE TABLE IF NOT EXISTS docker_registries (
	name       TEXT PRIMARY KEY,
	server     TEXT NOT NULL,
	username   TEXT NOT NULL,
	password   TEXT NOT NULL,
	created_at INTEGER NOT NULL
)`

const (
	settingComposeDir    = "compose_dir"
	settingDockerRoot    = "docker_root"
	settingInstallSecret = "install_secret" // per-install 加密密钥种子(base64)
)

// newDockStore 建表(幂等)并返回辅助。
func newDockStore(st *store.Store) (*dockStore, error) {
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createRegistriesTable); err != nil {
		return nil, err
	}
	return &dockStore{db: st.DB}, nil
}

// installSecret 返回 per-install 加密 secret,首次调用时生成并持久化。
func (s *dockStore) installSecret() (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM docker_settings WHERE key = ?`, settingInstallSecret).Scan(&v)
	if err == nil && v != "" {
		return v, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	secret, err := newInstallSecret()
	if err != nil {
		return "", err
	}
	if _, err := s.db.Exec(
		`INSERT INTO docker_settings (key, value) VALUES (?, ?)
			ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		settingInstallSecret, secret); err != nil {
		return "", err
	}
	return secret, nil
}

// Registry 是一个镜像仓库凭证记录。Password 仅写入用,读出时屏蔽为空。
type Registry struct {
	Name      string `json:"name"`
	Server    string `json:"server"`
	Username  string `json:"username"`
	Password  string `json:"password,omitempty"` // 写入用;列表读出时为空
	CreatedAt int64  `json:"created_at"`
}

// listRegistries 返回所有仓库,密码字段一律屏蔽。
func (s *dockStore) listRegistries() ([]Registry, error) {
	rows, err := s.db.Query(`SELECT name, server, username, created_at FROM docker_registries ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Registry, 0)
	for rows.Next() {
		var reg Registry
		if err := rows.Scan(&reg.Name, &reg.Server, &reg.Username, &reg.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, reg)
	}
	return out, rows.Err()
}

// saveRegistry upsert 一条仓库凭证,encPassword 为已加密密文。
func (s *dockStore) saveRegistry(reg Registry, encPassword string) error {
	const q = `INSERT INTO docker_registries (name, server, username, password, created_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			server = excluded.server,
			username = excluded.username,
			password = excluded.password`
	_, err := s.db.Exec(q, reg.Name, reg.Server, reg.Username, encPassword, reg.CreatedAt)
	return err
}

// deleteRegistry 删除一条仓库凭证,返回是否存在。
func (s *dockStore) deleteRegistry(name string) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM docker_registries WHERE name = ?`, name)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// loadSettings 读设置,缺失的 key 回退到默认值。
func (s *dockStore) loadSettings() (Settings, error) {
	out := DefaultSettings()
	rows, err := s.db.Query(`SELECT key, value FROM docker_settings`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return out, err
		}
		switch k {
		case settingComposeDir:
			out.ComposeDir = v
		case settingDockerRoot:
			out.DockerRoot = v
		}
	}
	return out, rows.Err()
}

// saveSettings upsert 两个设置 key。
func (s *dockStore) saveSettings(set Settings) error {
	const q = `INSERT INTO docker_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	if _, err := s.db.Exec(q, settingComposeDir, set.ComposeDir); err != nil {
		return err
	}
	_, err := s.db.Exec(q, settingDockerRoot, set.DockerRoot)
	return err
}
