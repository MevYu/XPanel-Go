package users

import (
	"database/sql"
	"errors"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// errNotFound 模块内查询无记录时返回。
var errNotFound = errors.New("users: not found")

// userStore 是本模块私有 DB 辅助:自建 user_totp / api_keys / user_settings 表(幂等),
// 并对中央 users 表做只读/行级写(不改其 schema)。
type userStore struct{ db *sql.DB }

// UserInfo 是对外暴露的用户视图,不含密码哈希。TOTPEnabled 由 user_totp 联表得出。
type UserInfo struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Role        string `json:"role"`
	CreatedAt   int64  `json:"created_at"`
	TOTPEnabled bool   `json:"totp_enabled"`
}

// APIKeyInfo 是 API Key 的元数据视图,绝不含明文或哈希。
type APIKeyInfo struct {
	ID         int64  `json:"id"`
	UserID     int64  `json:"user_id"`
	Name       string `json:"name"`
	CreatedAt  int64  `json:"created_at"`
	LastUsedAt *int64 `json:"last_used_at"`
}

const createTOTPTable = `CREATE TABLE IF NOT EXISTS user_totp (
	user_id        INTEGER PRIMARY KEY,
	secret_enc     TEXT NOT NULL,
	enabled        INTEGER NOT NULL DEFAULT 0,
	created_at     INTEGER NOT NULL,
	FOREIGN KEY(user_id) REFERENCES users(id)
)`

const createAPIKeysTable = `CREATE TABLE IF NOT EXISTS api_keys (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id      INTEGER NOT NULL,
	name         TEXT NOT NULL DEFAULT '',
	key_hash     TEXT NOT NULL UNIQUE,
	created_at   INTEGER NOT NULL,
	last_used_at INTEGER,
	FOREIGN KEY(user_id) REFERENCES users(id)
)`

const createSettingsTable = `CREATE TABLE IF NOT EXISTS user_settings (
	key   TEXT PRIMARY KEY,
	value TEXT NOT NULL
)`

// newUserStore 建表(幂等)并返回辅助。
func newUserStore(st *store.Store) (*userStore, error) {
	for _, ddl := range []string{createTOTPTable, createAPIKeysTable, createSettingsTable} {
		if _, err := st.DB.Exec(ddl); err != nil {
			return nil, err
		}
	}
	return &userStore{db: st.DB}, nil
}

// --- users (中央表,只读 + 行级写) ---

func (s *userStore) listUsers() ([]UserInfo, error) {
	rows, err := s.db.Query(`SELECT u.id, u.username, u.role, u.created_at,
		COALESCE(t.enabled, 0)
		FROM users u LEFT JOIN user_totp t ON t.user_id = u.id
		ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserInfo
	for rows.Next() {
		var u UserInfo
		var enabled int
		if err := rows.Scan(&u.ID, &u.Username, &u.Role, &u.CreatedAt, &enabled); err != nil {
			return nil, err
		}
		u.TOTPEnabled = enabled != 0
		out = append(out, u)
	}
	return out, rows.Err()
}

func (s *userStore) userExists(id int64) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE id = ?`, id).Scan(&n)
	return n > 0, err
}

func (s *userStore) usernameTaken(username string) (bool, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE username = ?`, username).Scan(&n)
	return n > 0, err
}

func (s *userStore) createUser(username, passHash, role string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO users (username, pass_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		username, passHash, role, time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// deleteUser 删除用户及其 TOTP / API Key(同事务,避免孤儿行)。
func (s *userStore) deleteUser(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM api_keys WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM user_totp WHERE user_id = ?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM users WHERE id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *userStore) setRole(id int64, role string) error {
	_, err := s.db.Exec(`UPDATE users SET role = ? WHERE id = ?`, role, id)
	return err
}

func (s *userStore) setPassword(id int64, passHash string) error {
	_, err := s.db.Exec(`UPDATE users SET pass_hash = ? WHERE id = ?`, passHash, id)
	return err
}

func (s *userStore) countAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role = 'admin'`).Scan(&n)
	return n, err
}

func (s *userStore) getRole(id int64) (string, error) {
	var role string
	err := s.db.QueryRow(`SELECT role FROM users WHERE id = ?`, id).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errNotFound
	}
	return role, err
}

// --- TOTP ---

type totpRow struct {
	SecretEnc string
	Enabled   bool
}

// upsertTOTP 写入(或覆盖)某用户的加密密钥,enabled 置为给定值。
func (s *userStore) upsertTOTP(userID int64, secretEnc string, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	_, err := s.db.Exec(`INSERT INTO user_totp (user_id, secret_enc, enabled, created_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET secret_enc = excluded.secret_enc, enabled = excluded.enabled`,
		userID, secretEnc, en, time.Now().Unix())
	return err
}

func (s *userStore) getTOTP(userID int64) (totpRow, error) {
	var row totpRow
	var enabled int
	err := s.db.QueryRow(`SELECT secret_enc, enabled FROM user_totp WHERE user_id = ?`, userID).
		Scan(&row.SecretEnc, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return totpRow{}, errNotFound
	}
	row.Enabled = enabled != 0
	return row, err
}

func (s *userStore) setTOTPEnabled(userID int64, enabled bool) error {
	en := 0
	if enabled {
		en = 1
	}
	res, err := s.db.Exec(`UPDATE user_totp SET enabled = ? WHERE user_id = ?`, en, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errNotFound
	}
	return nil
}

func (s *userStore) deleteTOTP(userID int64) error {
	_, err := s.db.Exec(`DELETE FROM user_totp WHERE user_id = ?`, userID)
	return err
}

// --- API Keys ---

func (s *userStore) createAPIKey(userID int64, name, keyHash string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO api_keys (user_id, name, key_hash, created_at) VALUES (?, ?, ?, ?)`,
		userID, name, keyHash, time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *userStore) listAPIKeys(userID int64) ([]APIKeyInfo, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY id`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKeyInfo
	for rows.Next() {
		var k APIKeyInfo
		var last sql.NullInt64
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.CreatedAt, &last); err != nil {
			return nil, err
		}
		if last.Valid {
			k.LastUsedAt = &last.Int64
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// revokeAPIKey 删除某用户名下的指定 key。返回是否命中(防越权吊销他人 key)。
func (s *userStore) revokeAPIKey(userID, keyID int64) (bool, error) {
	res, err := s.db.Exec(`DELETE FROM api_keys WHERE id = ? AND user_id = ?`, keyID, userID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// --- settings ---

func (s *userStore) getSetting(key, def string) (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM user_settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return def, nil
	}
	return v, err
}

func (s *userStore) setSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO user_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}
