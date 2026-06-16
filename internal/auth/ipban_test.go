package auth

import (
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestIPBanAfterThreshold(t *testing.T) {
	st := newTestStore(t)
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	g, err := NewIPBanGuard(st, 3, 72*time.Hour, clock)
	if err != nil {
		t.Fatalf("NewIPBanGuard: %v", err)
	}

	ip := "1.2.3.4"
	if g.Banned(ip) {
		t.Fatal("fresh ip must not be banned")
	}
	g.Fail(ip)
	g.Fail(ip)
	if g.Banned(ip) {
		t.Fatal("under threshold must not ban")
	}
	g.Fail(ip) // 第 3 次触发封禁
	if !g.Banned(ip) {
		t.Fatal("threshold reached should ban")
	}
}

func TestIPBanExpires(t *testing.T) {
	st := newTestStore(t)
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	g, _ := NewIPBanGuard(st, 3, 72*time.Hour, clock)

	ip := "5.6.7.8"
	g.Fail(ip)
	g.Fail(ip)
	g.Fail(ip)
	if !g.Banned(ip) {
		t.Fatal("should be banned")
	}
	now = now.Add(73 * time.Hour)
	if g.Banned(ip) {
		t.Fatal("ban should expire after duration")
	}
}

func TestIPBanPersistsAcrossRestart(t *testing.T) {
	st := newTestStore(t)
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	g, _ := NewIPBanGuard(st, 3, 72*time.Hour, clock)

	ip := "9.9.9.9"
	g.Fail(ip)
	g.Fail(ip)
	g.Fail(ip)
	if !g.Banned(ip) {
		t.Fatal("should be banned")
	}

	// 模拟重启:新守卫从同一 store 载入活跃封禁。
	g2, err := NewIPBanGuard(st, 3, 72*time.Hour, clock)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !g2.Banned(ip) {
		t.Fatal("ban must survive restart (loaded from store)")
	}

	// 到期后重启不应再视为封禁。
	now = now.Add(73 * time.Hour)
	g3, _ := NewIPBanGuard(st, 3, 72*time.Hour, clock)
	if g3.Banned(ip) {
		t.Fatal("expired ban must not load after restart")
	}
}

func TestIPBanThresholdConfigurable(t *testing.T) {
	st := newTestStore(t)
	clock := func() time.Time { return time.Unix(1000, 0) }
	g, _ := NewIPBanGuard(st, 5, time.Hour, clock)

	ip := "2.2.2.2"
	for i := 0; i < 4; i++ {
		g.Fail(ip)
	}
	if g.Banned(ip) {
		t.Fatal("4 failures under threshold 5 must not ban")
	}
	g.Fail(ip)
	if !g.Banned(ip) {
		t.Fatal("5th failure should ban at threshold 5")
	}
}

func TestIPBanResetClearsFailures(t *testing.T) {
	st := newTestStore(t)
	clock := func() time.Time { return time.Unix(1000, 0) }
	g, _ := NewIPBanGuard(st, 3, time.Hour, clock)

	ip := "3.3.3.3"
	g.Fail(ip)
	g.Fail(ip)
	g.Reset(ip) // 成功登录清计数
	g.Fail(ip)
	g.Fail(ip)
	if g.Banned(ip) {
		t.Fatal("reset must clear failure count before threshold")
	}
}
