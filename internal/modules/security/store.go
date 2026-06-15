package security

import (
	"database/sql"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Settings 是模块可配置的路径/参数,经 GET/PUT /settings 修改(admin)。
type Settings struct {
	SSHDConfigPath    string `json:"sshd_config_path"`
	Fail2banConfigDir string `json:"fail2ban_config_dir"`
	AuthorizedKeys    string `json:"authorized_keys_path"`
}

// defaultSettings 是首启时写入的缺省值。
func defaultSettings() Settings {
	return Settings{
		SSHDConfigPath:    "/etc/ssh/sshd_config",
		Fail2banConfigDir: "/etc/fail2ban/jail.d",
		AuthorizedKeys:    "/root/.ssh/authorized_keys",
	}
}

// SSHKey 是一条受面板管理的 authorized_keys 公钥元数据。
type SSHKey struct {
	ID        int64  `json:"id"`
	Comment   string `json:"comment"`
	PublicKey string `json:"public_key"`
	CreatedBy *int64 `json:"created_by"`
	CreatedAt int64  `json:"created_at"`
}

// secStore 是本模块私有 DB 辅助:自建表,管 settings 与 ssh_keys 元数据。
// 不动中央 migrations,建表幂等。
type secStore struct{ db *sql.DB }

const createSettingsTable = `CREATE TABLE IF NOT EXISTS security_settings (
	id                  INTEGER PRIMARY KEY CHECK (id = 1),
	sshd_config_path    TEXT NOT NULL,
	fail2ban_config_dir TEXT NOT NULL,
	authorized_keys     TEXT NOT NULL
)`

const createKeysTable = `CREATE TABLE IF NOT EXISTS security_ssh_keys (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	comment    TEXT NOT NULL DEFAULT '',
	public_key TEXT NOT NULL UNIQUE,
	created_by INTEGER,
	created_at INTEGER NOT NULL
)`

// newSecStore 建表(幂等)、确保单行 settings 存在,返回辅助。
func newSecStore(st *store.Store) (*secStore, error) {
	if _, err := st.DB.Exec(createSettingsTable); err != nil {
		return nil, err
	}
	if _, err := st.DB.Exec(createKeysTable); err != nil {
		return nil, err
	}
	s := &secStore{db: st.DB}
	d := defaultSettings()
	// 幂等播种:仅当第 1 行不存在时写入缺省。
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO security_settings
		(id, sshd_config_path, fail2ban_config_dir, authorized_keys)
		VALUES (1, ?, ?, ?)`, d.SSHDConfigPath, d.Fail2banConfigDir, d.AuthorizedKeys); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *secStore) getSettings() (Settings, error) {
	var st Settings
	err := s.db.QueryRow(`SELECT sshd_config_path, fail2ban_config_dir, authorized_keys
		FROM security_settings WHERE id = 1`).Scan(
		&st.SSHDConfigPath, &st.Fail2banConfigDir, &st.AuthorizedKeys)
	return st, err
}

func (s *secStore) putSettings(st Settings) error {
	_, err := s.db.Exec(`UPDATE security_settings
		SET sshd_config_path = ?, fail2ban_config_dir = ?, authorized_keys = ?
		WHERE id = 1`, st.SSHDConfigPath, st.Fail2banConfigDir, st.AuthorizedKeys)
	return err
}

func (s *secStore) listKeys() ([]SSHKey, error) {
	rows, err := s.db.Query(`SELECT id, comment, public_key, created_by, created_at
		FROM security_ssh_keys ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []SSHKey
	for rows.Next() {
		var k SSHKey
		var createdBy sql.NullInt64
		if err := rows.Scan(&k.ID, &k.Comment, &k.PublicKey, &createdBy, &k.CreatedAt); err != nil {
			return nil, err
		}
		if createdBy.Valid {
			k.CreatedBy = &createdBy.Int64
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}

func (s *secStore) addKey(comment, publicKey string, createdBy *int64) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO security_ssh_keys (comment, public_key, created_by, created_at)
		VALUES (?, ?, ?, ?)`, comment, publicKey, createdBy, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *secStore) getKey(id int64) (SSHKey, error) {
	var k SSHKey
	var createdBy sql.NullInt64
	err := s.db.QueryRow(`SELECT id, comment, public_key, created_by, created_at
		FROM security_ssh_keys WHERE id = ?`, id).Scan(
		&k.ID, &k.Comment, &k.PublicKey, &createdBy, &k.CreatedAt)
	if err != nil {
		return SSHKey{}, err
	}
	if createdBy.Valid {
		k.CreatedBy = &createdBy.Int64
	}
	return k, nil
}

func (s *secStore) deleteKey(id int64) error {
	_, err := s.db.Exec(`DELETE FROM security_ssh_keys WHERE id = ?`, id)
	return err
}
