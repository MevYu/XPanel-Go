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
	UserID  int64 // 签发该对的用户 ID;供调用方种登录态 cookie,不进 JSON 响应。
}

type Service struct {
	store   *store.Store
	jwt     *JWTManager
	lockout *Lockout
	ipban   *IPBanGuard // 可为 nil:不启用 IP 级封禁(如基础 server.New)
}

func NewService(s *store.Store, jwt *JWTManager, lo *Lockout) *Service {
	return &Service{store: s, jwt: jwt, lockout: lo}
}

// WithIPBan 注入 IP 封禁守卫,失败计数达阈值即封禁来源 IP。返回自身便于链式构造。
func (s *Service) WithIPBan(g *IPBanGuard) *Service {
	s.ipban = g
	return s
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
// 不涉及 2FA 的调用方仍可直接用此方法。需要 2FA 门的调用方改用 VerifyPassword + IssueFor。
func (s *Service) Login(username, password, ip string) (Tokens, error) {
	u, err := s.VerifyPassword(username, password, ip)
	if err != nil {
		return Tokens{}, err
	}
	_ = s.store.WriteAudit(&u.ID, "login.success", "", ip)
	return s.IssueFor(u.ID, u.Role)
}

// VerifyPassword 只校验用户名+密码,成功返回用户;失败计入锁定并写 login.failure 审计。
// 不签发 token、不写 login.success(留给调用方在通过后续门槛后写)。
// 防枚举(时序抹平)与登录锁定语义与原 Login 一致。
func (s *Service) VerifyPassword(username, password, ip string) (store.User, error) {
	key := username + "@" + ip
	if s.lockout.Locked(key) {
		return store.User{}, ErrLockedOut
	}
	u, err := s.store.GetUserByUsername(username)
	if err != nil {
		VerifyPassword(dummyHash(), password) // 抹平时序,结果丢弃
		s.failLogin(key, ip, username)
		return store.User{}, ErrInvalidCredentials
	}
	if !VerifyPassword(u.PassHash, password) {
		s.failLogin(key, ip, username)
		return store.User{}, ErrInvalidCredentials
	}
	s.lockout.Reset(key)
	if s.ipban != nil {
		s.ipban.Reset(ip)
	}
	return u, nil
}

// failLogin 记一次登录失败:写审计、刷新 username@ip 锁定、并累计 IP 级封禁计数。
func (s *Service) failLogin(key, ip, username string) {
	s.lockout.Fail(key)
	if s.ipban != nil {
		s.ipban.Fail(ip)
	}
	_ = s.store.WriteAudit(nil, "login.failure", username, ip)
}

// Refresh 旋转:校验旧 refresh → 原子消费 → 只有赢者发新对。
// 原子撤销关闭了 SELECT-then-UPDATE 的竞争窗口,防止同一 refresh 并发双花。
func (s *Service) Refresh(refresh, ip string) (Tokens, error) {
	rt, err := s.store.GetValidRefreshToken(refresh)
	if err != nil {
		return Tokens{}, ErrInvalidCredentials
	}
	won, err := s.store.RevokeRefreshTokenIfActive(refresh)
	if err != nil {
		return Tokens{}, err
	}
	if !won {
		return Tokens{}, ErrInvalidCredentials
	}
	user, err := s.store.GetUserByID(rt.UserID)
	if err != nil {
		return Tokens{}, ErrInvalidCredentials
	}
	_ = s.store.WriteAudit(&user.ID, "token.refresh", "", ip)
	return s.IssueFor(user.ID, user.Role)
}

func (s *Service) Logout(refresh, ip string) error {
	_ = s.store.WriteAudit(nil, "logout", "", ip)
	return s.store.RevokeRefreshToken(refresh)
}

// Audit 写一条登录相关审计。供拆分登录流程(密码门 + 2FA 门)的调用方记录最终结果。
func (s *Service) Audit(userID *int64, action, detail, ip string) {
	_ = s.store.WriteAudit(userID, action, detail, ip)
}

// IssueFor 为已认证用户签发 access+refresh,不做任何鉴权。调用方负责确保身份已校验。
func (s *Service) IssueFor(userID int64, role string) (Tokens, error) {
	access, err := s.jwt.Issue(userID, role)
	if err != nil {
		return Tokens{}, err
	}
	refresh, err := s.store.CreateRefreshToken(userID, time.Now().Add(refreshTTL).Unix())
	if err != nil {
		return Tokens{}, err
	}
	return Tokens{Access: access, Refresh: refresh, UserID: userID}, nil
}
