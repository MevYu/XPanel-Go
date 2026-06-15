package auth

import (
	"errors"
	"sync"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrLockedOut          = errors.New("auth: too many failed attempts")
)

const refreshTTL = 7 * 24 * time.Hour

// dummyHash 在用户不存在时仍跑一次等价的 argon2 校验,抹平时序差,防止用户名枚举。
var dummyHash = sync.OnceValue(func() string {
	h, _ := HashPassword("xpanel-timing-equalizer")
	return h
})

type Tokens struct {
	Access  string
	Refresh string
}

type Service struct {
	store   *store.Store
	jwt     *JWTManager
	lockout *Lockout
}

func NewService(s *store.Store, jwt *JWTManager, lo *Lockout) *Service {
	return &Service{store: s, jwt: jwt, lockout: lo}
}

// Register 创建用户;密码在此哈希。调用方负责鉴权(如首启 bootstrap)。
func (s *Service) Register(username, password, role string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	_, err = s.store.CreateUser(username, hash, role)
	return err
}

// Login 校验密码,成功签发 access+refresh,失败计入锁定。lockKey = username@ip。
func (s *Service) Login(username, password, ip string) (Tokens, error) {
	key := username + "@" + ip
	if s.lockout.Locked(key) {
		return Tokens{}, ErrLockedOut
	}
	u, err := s.store.GetUserByUsername(username)
	if err != nil {
		VerifyPassword(dummyHash(), password) // 抹平时序,结果丢弃
		s.lockout.Fail(key)
		_ = s.store.WriteAudit(nil, "login.failure", username, ip)
		return Tokens{}, ErrInvalidCredentials
	}
	if !VerifyPassword(u.PassHash, password) {
		s.lockout.Fail(key)
		_ = s.store.WriteAudit(nil, "login.failure", username, ip)
		return Tokens{}, ErrInvalidCredentials
	}
	s.lockout.Reset(key)
	_ = s.store.WriteAudit(&u.ID, "login.success", "", ip)
	return s.issue(u.ID, u.Role)
}

// Refresh 旋转:校验旧 refresh → 撤销 → 发新对。
func (s *Service) Refresh(refresh, ip string) (Tokens, error) {
	rt, err := s.store.GetValidRefreshToken(refresh)
	if err != nil {
		return Tokens{}, ErrInvalidCredentials
	}
	user, err := s.store.GetUserByID(rt.UserID)
	if err != nil {
		return Tokens{}, ErrInvalidCredentials
	}
	if err := s.store.RevokeRefreshToken(refresh); err != nil {
		return Tokens{}, err
	}
	_ = s.store.WriteAudit(&user.ID, "token.refresh", "", ip)
	return s.issue(user.ID, user.Role)
}

func (s *Service) Logout(refresh, ip string) error {
	_ = s.store.WriteAudit(nil, "logout", "", ip)
	return s.store.RevokeRefreshToken(refresh)
}

func (s *Service) issue(userID int64, role string) (Tokens, error) {
	access, err := s.jwt.Issue(userID, role)
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := s.store.CreateRefreshToken(userID, time.Now().Add(refreshTTL).Unix())
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{Access: access, Refresh: refresh}, nil
}
