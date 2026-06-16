package database

import (
	"database/sql"
	"errors"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// Settings 是本模块可配置的路径与连接信息。覆盖值落库,未设置则用默认值。
// 密码字段在落库时 AES-GCM 加密,API 输出一律屏蔽(从不回传明文)。
type Settings struct {
	// MySQL/MariaDB 连接
	MySQLHost     string `json:"mysql_host"`
	MySQLPort     int    `json:"mysql_port"`
	MySQLSocket   string `json:"mysql_socket"` // 非空则优先于 host:port
	MySQLUser     string `json:"mysql_user"`
	MySQLPassword string `json:"mysql_password"` // 写入用;读出时屏蔽为空
	MySQLDataDir  string `json:"mysql_data_dir"`

	// PostgreSQL 连接
	PGHost     string `json:"pg_host"`
	PGPort     int    `json:"pg_port"`
	PGUser     string `json:"pg_user"`
	PGPassword string `json:"pg_password"` // 写入用;读出时屏蔽为空
	PGDataDir  string `json:"pg_data_dir"`

	// Redis 连接
	RedisHost     string `json:"redis_host"`
	RedisPort     int    `json:"redis_port"`
	RedisPassword string `json:"redis_password"` // 写入用;读出时屏蔽为空

	// 备份目录(列库导出/转储落盘位置)
	BackupDir string `json:"backup_dir"`

	// 导出/导入工具路径(空则用默认名,经 PATH 解析)。非空须为安全路径。
	MySQLDumpBin string `json:"mysqldump_bin"`
	MySQLCLIBin  string `json:"mysql_cli_bin"`
	PGDumpBin    string `json:"pg_dump_bin"`
	PGRestoreBin string `json:"pg_restore_bin"`
}

// defaultSettings 返回各路径/连接的合理默认值。
func defaultSettings() Settings {
	return Settings{
		MySQLHost:    "127.0.0.1",
		MySQLPort:    3306,
		MySQLUser:    "root",
		MySQLDataDir: "/var/lib/mysql",

		PGHost:    "127.0.0.1",
		PGPort:    5432,
		PGUser:    "postgres",
		PGDataDir: "/var/lib/postgresql/data",

		RedisHost: "127.0.0.1",
		RedisPort: 6379,

		BackupDir: "/var/backups/xpanel/database",
	}
}

// settingsSchema 幂等建表:单行 KV(每个字段一列),id 固定为 1。
// 密码列存密文(AES-GCM base64),其余存明文。
const settingsSchema = `CREATE TABLE IF NOT EXISTS database_settings (
	id              INTEGER PRIMARY KEY CHECK (id = 1),
	mysql_host      TEXT NOT NULL DEFAULT '',
	mysql_port      INTEGER NOT NULL DEFAULT 0,
	mysql_socket    TEXT NOT NULL DEFAULT '',
	mysql_user      TEXT NOT NULL DEFAULT '',
	mysql_password  TEXT NOT NULL DEFAULT '',
	mysql_data_dir  TEXT NOT NULL DEFAULT '',
	pg_host         TEXT NOT NULL DEFAULT '',
	pg_port         INTEGER NOT NULL DEFAULT 0,
	pg_user         TEXT NOT NULL DEFAULT '',
	pg_password     TEXT NOT NULL DEFAULT '',
	pg_data_dir     TEXT NOT NULL DEFAULT '',
	redis_host      TEXT NOT NULL DEFAULT '',
	redis_port      INTEGER NOT NULL DEFAULT 0,
	redis_password  TEXT NOT NULL DEFAULT '',
	backup_dir      TEXT NOT NULL DEFAULT '',
	mysqldump_bin   TEXT NOT NULL DEFAULT '',
	mysql_cli_bin   TEXT NOT NULL DEFAULT '',
	pg_dump_bin     TEXT NOT NULL DEFAULT '',
	pg_restore_bin  TEXT NOT NULL DEFAULT ''
)`

// settingsStore 读写 database_settings 单行,加解密密码列。
type settingsStore struct {
	db   *sql.DB
	cryp *cryptor
}

// addColumns 是对已存在表的幂等列补充(老表升级)。CREATE TABLE IF NOT EXISTS 不会改老表结构。
var addColumns = []string{
	`ALTER TABLE database_settings ADD COLUMN mysqldump_bin  TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE database_settings ADD COLUMN mysql_cli_bin  TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE database_settings ADD COLUMN pg_dump_bin    TEXT NOT NULL DEFAULT ''`,
	`ALTER TABLE database_settings ADD COLUMN pg_restore_bin TEXT NOT NULL DEFAULT ''`,
}

func newSettingsStore(st *store.Store, cryp *cryptor) (*settingsStore, error) {
	if _, err := st.DB.Exec(settingsSchema); err != nil {
		return nil, err
	}
	// 幂等补列:列已存在时 ALTER 报错,忽略(SQLite 无 ADD COLUMN IF NOT EXISTS)。
	for _, stmt := range addColumns {
		_, _ = st.DB.Exec(stmt)
	}
	return &settingsStore{db: st.DB, cryp: cryp}, nil
}

// effective 返回有效设置:已落库的覆盖值盖在默认值上,密码字段解密为明文(供内部建连用)。
func (s *settingsStore) effective() (Settings, error) {
	cur := defaultSettings()
	var encMySQL, encPG, encRedis string
	row := s.db.QueryRow(`SELECT mysql_host, mysql_port, mysql_socket, mysql_user, mysql_password, mysql_data_dir,
		pg_host, pg_port, pg_user, pg_password, pg_data_dir,
		redis_host, redis_port, redis_password, backup_dir,
		mysqldump_bin, mysql_cli_bin, pg_dump_bin, pg_restore_bin
		FROM database_settings WHERE id = 1`)
	var got Settings
	err := row.Scan(&got.MySQLHost, &got.MySQLPort, &got.MySQLSocket, &got.MySQLUser, &encMySQL, &got.MySQLDataDir,
		&got.PGHost, &got.PGPort, &got.PGUser, &encPG, &got.PGDataDir,
		&got.RedisHost, &got.RedisPort, &encRedis, &got.BackupDir,
		&got.MySQLDumpBin, &got.MySQLCLIBin, &got.PGDumpBin, &got.PGRestoreBin)
	if errors.Is(err, sql.ErrNoRows) {
		return cur, nil // 未配置 → 默认
	}
	if err != nil {
		return Settings{}, err
	}
	overlay(&cur, got)
	for _, d := range []struct {
		enc string
		dst *string
	}{{encMySQL, &cur.MySQLPassword}, {encPG, &cur.PGPassword}, {encRedis, &cur.RedisPassword}} {
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
	if eff.MySQLPassword != "" {
		set = append(set, "mysql")
	}
	if eff.PGPassword != "" {
		set = append(set, "pg")
	}
	if eff.RedisPassword != "" {
		set = append(set, "redis")
	}
	eff.MySQLPassword, eff.PGPassword, eff.RedisPassword = "", "", ""
	return eff, set, nil
}

// save 覆盖单行设置。密码非空则加密落库;空串保留原密文(不清空)。
func (s *settingsStore) save(in Settings) error {
	prev, err := s.rawPasswords()
	if err != nil {
		return err
	}
	encMySQL, err := s.encOrKeep(in.MySQLPassword, prev[0])
	if err != nil {
		return err
	}
	encPG, err := s.encOrKeep(in.PGPassword, prev[1])
	if err != nil {
		return err
	}
	encRedis, err := s.encOrKeep(in.RedisPassword, prev[2])
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT INTO database_settings
		(id, mysql_host, mysql_port, mysql_socket, mysql_user, mysql_password, mysql_data_dir,
		 pg_host, pg_port, pg_user, pg_password, pg_data_dir,
		 redis_host, redis_port, redis_password, backup_dir,
		 mysqldump_bin, mysql_cli_bin, pg_dump_bin, pg_restore_bin)
		VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		 mysql_host=excluded.mysql_host, mysql_port=excluded.mysql_port, mysql_socket=excluded.mysql_socket,
		 mysql_user=excluded.mysql_user, mysql_password=excluded.mysql_password, mysql_data_dir=excluded.mysql_data_dir,
		 pg_host=excluded.pg_host, pg_port=excluded.pg_port, pg_user=excluded.pg_user,
		 pg_password=excluded.pg_password, pg_data_dir=excluded.pg_data_dir,
		 redis_host=excluded.redis_host, redis_port=excluded.redis_port, redis_password=excluded.redis_password,
		 backup_dir=excluded.backup_dir,
		 mysqldump_bin=excluded.mysqldump_bin, mysql_cli_bin=excluded.mysql_cli_bin,
		 pg_dump_bin=excluded.pg_dump_bin, pg_restore_bin=excluded.pg_restore_bin`,
		in.MySQLHost, in.MySQLPort, in.MySQLSocket, in.MySQLUser, encMySQL, in.MySQLDataDir,
		in.PGHost, in.PGPort, in.PGUser, encPG, in.PGDataDir,
		in.RedisHost, in.RedisPort, encRedis, in.BackupDir,
		in.MySQLDumpBin, in.MySQLCLIBin, in.PGDumpBin, in.PGRestoreBin)
	return err
}

// encOrKeep:新密码非空 → 加密;为空 → 保留旧密文。
func (s *settingsStore) encOrKeep(plain, prevEnc string) (string, error) {
	if plain == "" {
		return prevEnc, nil
	}
	return s.cryp.encrypt(plain)
}

// rawPasswords 取当前落库的三个密码密文(无行则全空)。
func (s *settingsStore) rawPasswords() ([3]string, error) {
	var out [3]string
	row := s.db.QueryRow(`SELECT mysql_password, pg_password, redis_password FROM database_settings WHERE id = 1`)
	err := row.Scan(&out[0], &out[1], &out[2])
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	return out, err
}

// overlay 把 got 中的非零字段盖到 dst(零值视为"未设",用默认)。
func overlay(dst *Settings, got Settings) {
	if got.MySQLHost != "" {
		dst.MySQLHost = got.MySQLHost
	}
	if got.MySQLPort != 0 {
		dst.MySQLPort = got.MySQLPort
	}
	if got.MySQLSocket != "" {
		dst.MySQLSocket = got.MySQLSocket
	}
	if got.MySQLUser != "" {
		dst.MySQLUser = got.MySQLUser
	}
	if got.MySQLDataDir != "" {
		dst.MySQLDataDir = got.MySQLDataDir
	}
	if got.PGHost != "" {
		dst.PGHost = got.PGHost
	}
	if got.PGPort != 0 {
		dst.PGPort = got.PGPort
	}
	if got.PGUser != "" {
		dst.PGUser = got.PGUser
	}
	if got.PGDataDir != "" {
		dst.PGDataDir = got.PGDataDir
	}
	if got.RedisHost != "" {
		dst.RedisHost = got.RedisHost
	}
	if got.RedisPort != 0 {
		dst.RedisPort = got.RedisPort
	}
	if got.BackupDir != "" {
		dst.BackupDir = got.BackupDir
	}
	if got.MySQLDumpBin != "" {
		dst.MySQLDumpBin = got.MySQLDumpBin
	}
	if got.MySQLCLIBin != "" {
		dst.MySQLCLIBin = got.MySQLCLIBin
	}
	if got.PGDumpBin != "" {
		dst.PGDumpBin = got.PGDumpBin
	}
	if got.PGRestoreBin != "" {
		dst.PGRestoreBin = got.PGRestoreBin
	}
}
