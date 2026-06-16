package mysqlrepl

import (
	"database/sql"
	"errors"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Settings 是主从两端的连接信息。密码字段落库时 AES-GCM 加密,API 输出一律屏蔽。
type Settings struct {
	// 主库连接(在其上建复制用户、查 master status)
	MasterHost     string `json:"master_host"`
	MasterPort     int    `json:"master_port"`
	MasterUser     string `json:"master_user"`
	MasterPassword string `json:"master_password"` // 写入用;读出时屏蔽为空

	// 从库连接(在其上 CHANGE MASTER TO / start|stop slave)
	SlaveHost     string `json:"slave_host"`
	SlavePort     int    `json:"slave_port"`
	SlaveUser     string `json:"slave_user"`
	SlavePassword string `json:"slave_password"` // 写入用;读出时屏蔽为空
}

// defaultSettings 返回合理默认值(本机主库 3306、本机从库 3307)。
func defaultSettings() Settings {
	return Settings{
		MasterHost: "127.0.0.1",
		MasterPort: 3306,
		MasterUser: "root",

		SlaveHost: "127.0.0.1",
		SlavePort: 3307,
		SlaveUser: "root",
	}
}

// settingsSchema 幂等建表:单行 KV,id 固定为 1。密码列存密文(AES-GCM base64)。
const settingsSchema = `CREATE TABLE IF NOT EXISTS mysqlrepl_settings (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	master_host     TEXT NOT NULL DEFAULT '',
	master_port     INTEGER NOT NULL DEFAULT 0,
	master_user     TEXT NOT NULL DEFAULT '',
	master_password TEXT NOT NULL DEFAULT '',
	slave_host      TEXT NOT NULL DEFAULT '',
	slave_port      INTEGER NOT NULL DEFAULT 0,
	slave_user      TEXT NOT NULL DEFAULT '',
	slave_password  TEXT NOT NULL DEFAULT ''
)`

// settingsStore 读写 mysqlrepl_settings 单行,加解密密码列。
type settingsStore struct {
	db   *sql.DB
	cryp *cryptor
}

func newSettingsStore(st *store.Store, cryp *cryptor) (*settingsStore, error) {
	if _, err := st.DB.Exec(settingsSchema); err != nil {
		return nil, err
	}
	return &settingsStore{db: st.DB, cryp: cryp}, nil
}

// effective 返回有效设置:已落库的覆盖值盖在默认值上,密码字段解密为明文(供内部建连用)。
func (s *settingsStore) effective() (Settings, error) {
	cur := defaultSettings()
	var encMaster, encSlave string
	var got Settings
	row := s.db.QueryRow(`SELECT master_host, master_port, master_user, master_password,
		slave_host, slave_port, slave_user, slave_password
		FROM mysqlrepl_settings WHERE id = 1`)
	err := row.Scan(&got.MasterHost, &got.MasterPort, &got.MasterUser, &encMaster,
		&got.SlaveHost, &got.SlavePort, &got.SlaveUser, &encSlave)
	if errors.Is(err, sql.ErrNoRows) {
		return cur, nil
	}
	if err != nil {
		return Settings{}, err
	}
	overlay(&cur, got)
	for _, d := range []struct {
		enc string
		dst *string
	}{{encMaster, &cur.MasterPassword}, {encSlave, &cur.SlavePassword}} {
		plain, derr := s.cryp.decrypt(d.enc)
		if derr != nil {
			return Settings{}, derr
		}
		*d.dst = plain
	}
	return cur, nil
}

// masked 返回有效设置但抹掉所有密码(供 GET /settings 输出,只标示是否已设)。
func (s *settingsStore) masked() (Settings, []string, error) {
	eff, err := s.effective()
	if err != nil {
		return Settings{}, nil, err
	}
	var set []string
	if eff.MasterPassword != "" {
		set = append(set, "master")
	}
	if eff.SlavePassword != "" {
		set = append(set, "slave")
	}
	eff.MasterPassword, eff.SlavePassword = "", ""
	return eff, set, nil
}

// save 覆盖单行设置。密码非空则加密落库;空串保留原密文(不清空)。
func (s *settingsStore) save(in Settings) error {
	prev, err := s.rawPasswords()
	if err != nil {
		return err
	}
	encMaster, err := s.encOrKeep(in.MasterPassword, prev[0])
	if err != nil {
		return err
	}
	encSlave, err := s.encOrKeep(in.SlavePassword, prev[1])
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO mysqlrepl_settings
		(id, master_host, master_port, master_user, master_password,
		 slave_host, slave_port, slave_user, slave_password)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 master_host=excluded.master_host, master_port=excluded.master_port,
		 master_user=excluded.master_user, master_password=excluded.master_password,
		 slave_host=excluded.slave_host, slave_port=excluded.slave_port,
		 slave_user=excluded.slave_user, slave_password=excluded.slave_password`,
		in.MasterHost, in.MasterPort, in.MasterUser, encMaster,
		in.SlaveHost, in.SlavePort, in.SlaveUser, encSlave)
	return err
}

// encOrKeep:新密码非空 → 加密;为空 → 保留旧密文。
func (s *settingsStore) encOrKeep(plain, prevEnc string) (string, error) {
	if plain == "" {
		return prevEnc, nil
	}
	return s.cryp.encrypt(plain)
}

// rawPasswords 取当前落库的两个密码密文(无行则全空)。
func (s *settingsStore) rawPasswords() ([2]string, error) {
	var out [2]string
	row := s.db.QueryRow(`SELECT master_password, slave_password FROM mysqlrepl_settings WHERE id = 1`)
	err := row.Scan(&out[0], &out[1])
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, err
}

// overlay 把 got 中的非零字段盖到 dst(零值视为"未设",用默认)。
func overlay(dst *Settings, got Settings) {
	if got.MasterHost != "" {
		dst.MasterHost = got.MasterHost
	}
	if got.MasterPort != 0 {
		dst.MasterPort = got.MasterPort
	}
	if got.MasterUser != "" {
		dst.MasterUser = got.MasterUser
	}
	if got.SlaveHost != "" {
		dst.SlaveHost = got.SlaveHost
	}
	if got.SlavePort != 0 {
		dst.SlavePort = got.SlavePort
	}
	if got.SlaveUser != "" {
		dst.SlaveUser = got.SlaveUser
	}
}

func (s Settings) masterConn() connConfig {
	return connConfig{Host: s.MasterHost, Port: s.MasterPort, User: s.MasterUser, Password: s.MasterPassword}
}

func (s Settings) slaveConn() connConfig {
	return connConfig{Host: s.SlaveHost, Port: s.SlavePort, User: s.SlaveUser, Password: s.SlavePassword}
}
