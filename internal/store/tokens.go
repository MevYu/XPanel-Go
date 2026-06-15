package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

type RefreshToken struct {
	ID        string
	UserID    int64
	ExpiresAt int64
}

// CreateRefreshToken 生成 256-bit 随机 id 并入库,返回该 id(明文,交给客户端)。
func (s *Store) CreateRefreshToken(userID, expiresAt int64) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := hex.EncodeToString(buf)
	_, err := s.DB.Exec(
		`INSERT INTO refresh_tokens (id, user_id, expires_at, revoked) VALUES (?, ?, ?, 0)`,
		id, userID, expiresAt,
	)
	return id, err
}

// GetValidRefreshToken 仅返回未撤销且未过期的 token,否则 ErrNotFound。
func (s *Store) GetValidRefreshToken(id string) (RefreshToken, error) {
	var rt RefreshToken
	var revoked int
	err := s.DB.QueryRow(
		`SELECT id, user_id, expires_at, revoked FROM refresh_tokens WHERE id = ?`, id,
	).Scan(&rt.ID, &rt.UserID, &rt.ExpiresAt, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return RefreshToken{}, ErrNotFound
	}
	if err != nil {
		return RefreshToken{}, err
	}
	if revoked == 1 || rt.ExpiresAt < time.Now().Unix() {
		return RefreshToken{}, ErrNotFound
	}
	return rt, nil
}

func (s *Store) RevokeRefreshToken(id string) error {
	_, err := s.DB.Exec(`UPDATE refresh_tokens SET revoked = 1 WHERE id = ?`, id)
	return err
}

// RevokeRefreshTokenIfActive 原子地撤销一个未撤销、未过期的 token。
// 返回 true 表示本次确实由它完成撤销(赢得竞争);false 表示已被撤销/过期/不存在。
func (s *Store) RevokeRefreshTokenIfActive(id string) (bool, error) {
	res, err := s.DB.Exec(
		`UPDATE refresh_tokens SET revoked = 1 WHERE id = ? AND revoked = 0 AND expires_at > ?`,
		id, time.Now().Unix(),
	)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
