package store

import (
	"database/sql"
	"errors"
	"time"
)

// ErrNotFound 由所有 Get* 方法在无记录时返回。
var ErrNotFound = errors.New("store: not found")

type User struct {
	ID        int64
	Username  string
	PassHash  string
	Role      string
	CreatedAt int64
}

// CreateUser 插入新用户;用户名唯一,重复返回错误。
func (s *Store) CreateUser(username, passHash, role string) (User, error) {
	now := time.Now().Unix()
	res, err := s.DB.Exec(
		`INSERT INTO users (username, pass_hash, role, created_at) VALUES (?, ?, ?, ?)`,
		username, passHash, role, now,
	)
	if err != nil {
		return User{}, err
	}
	id, _ := res.LastInsertId()
	return User{ID: id, Username: username, PassHash: passHash, Role: role, CreatedAt: now}, nil
}

func (s *Store) GetUserByUsername(username string) (User, error) {
	var u User
	err := s.DB.QueryRow(
		`SELECT id, username, pass_hash, role, created_at FROM users WHERE username = ?`, username,
	).Scan(&u.ID, &u.Username, &u.PassHash, &u.Role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return u, err
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}
