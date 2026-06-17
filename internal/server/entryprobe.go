package server

import (
	"sync"
	"time"
)

// EntryProbeGuard 跟踪每 IP 在滑动窗口内命中隐藏入口 404(入口探测)的次数,
// 超过 max 即调 ban 封禁该 IP。计数仅驻内存(封禁本身已持久化),过期条目随访问清理。
type EntryProbeGuard struct {
	max    int
	window time.Duration
	ban    func(ip string)
	now    func() time.Time

	mu   sync.Mutex
	hits map[string][]time.Time // ip -> 窗口内命中时刻
}

// NewEntryProbeGuard 构造守卫。max 为窗口内允许的探测次数(> max 触发封禁),
// window 为滑动窗口时长,ban 在超阈值时被调以封禁该 IP。
func NewEntryProbeGuard(max int, window time.Duration, ban func(ip string), now func() time.Time) *EntryProbeGuard {
	return &EntryProbeGuard{
		max:    max,
		window: window,
		ban:    ban,
		now:    now,
		hits:   make(map[string][]time.Time),
	}
}

// SetThresholds 热更新探测阈值与窗口(设置端点改 config 后即时生效),持锁与 Probe 互斥。
func (g *EntryProbeGuard) SetThresholds(max int, window time.Duration) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.max = max
	g.window = window
}

// Probe 记该 IP 一次入口探测;窗口内累计次数 > max 时封禁该 IP 并清空其计数。
func (g *EntryProbeGuard) Probe(ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := g.now()
	cutoff := now.Add(-g.window)
	kept := g.hits[ip][:0]
	for _, t := range g.hits[ip] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	kept = append(kept, now)

	if len(kept) > g.max {
		delete(g.hits, ip)
		g.ban(ip)
		return
	}
	g.hits[ip] = kept
}
