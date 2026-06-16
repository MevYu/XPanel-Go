package auth

import (
	"sync"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// IPBanGuard 跟踪每 IP 的登录失败次数,达到 maxAttempts 即封禁该 IP banDuration。
// 封禁持久化到 store(跨重启生效),运行时用内存缓存避免每请求查库。
type IPBanGuard struct {
	store       *store.Store
	maxAttempts int
	banDuration time.Duration
	now         func() time.Time

	mu       sync.Mutex
	failures map[string]int   // ip -> 连续失败计数(仅内存,重启清零)
	banned   map[string]int64 // ip -> banned_until(Unix 秒),缓存活跃封禁
}

// NewIPBanGuard 构造守卫并从 store 载入未过期的封禁到内存缓存。
func NewIPBanGuard(s *store.Store, maxAttempts int, banDuration time.Duration, now func() time.Time) (*IPBanGuard, error) {
	g := &IPBanGuard{
		store:       s,
		maxAttempts: maxAttempts,
		banDuration: banDuration,
		now:         now,
		failures:    make(map[string]int),
		banned:      make(map[string]int64),
	}
	active, err := s.ActiveBans(now().Unix())
	if err != nil {
		return nil, err
	}
	for ip, until := range active {
		g.banned[ip] = until
	}
	return g, nil
}

// Banned 报告该 IP 当前是否在封禁期内。到期条目顺手清出缓存。
func (g *IPBanGuard) Banned(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	until, ok := g.banned[ip]
	if !ok {
		return false
	}
	if g.now().Unix() >= until {
		delete(g.banned, ip)
		_ = g.store.DeleteExpiredBans(g.now().Unix())
		return false
	}
	return true
}

// Fail 记一次该 IP 的登录失败;累计达到 maxAttempts 则封禁并持久化。
func (g *IPBanGuard) Fail(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failures[ip]++
	if g.failures[ip] < g.maxAttempts {
		return
	}
	until := g.now().Add(g.banDuration).Unix()
	g.banned[ip] = until
	delete(g.failures, ip)
	_ = g.store.BanIP(ip, until)
}

// Ban 立即封禁该 IP banDuration 并持久化,不经失败计数。
// 供登录之外的触发器(如入口探测防护)直接调用。
func (g *IPBanGuard) Ban(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	until := g.now().Add(g.banDuration).Unix()
	g.banned[ip] = until
	delete(g.failures, ip)
	_ = g.store.BanIP(ip, until)
}

// Reset 清除该 IP 的失败计数(登录成功时调用)。不解除已生效的封禁。
func (g *IPBanGuard) Reset(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, ip)
}
