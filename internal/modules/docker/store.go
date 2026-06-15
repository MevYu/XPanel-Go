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

const (
	settingComposeDir = "compose_dir"
	settingDockerRoot = "docker_root"
)

// newDockStore 建表(幂等)并返回辅助。
func newDockStore(st *store.Store) (*dockStore, error) {
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	return &dockStore{db: st.DB}, nil
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
