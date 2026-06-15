package auth

import (
	"testing"
	"time"
)

func TestLockoutAfterThreshold(t *testing.T) {
	now := time.Unix(1000, 0)
	clock := func() time.Time { return now }
	lo := NewLockout(3, time.Minute, clock)

	key := "user@1.2.3.4"
	if lo.Locked(key) {
		t.Fatal("fresh key must not be locked")
	}
	lo.Fail(key)
	lo.Fail(key)
	if lo.Locked(key) {
		t.Fatal("under threshold must not lock")
	}
	lo.Fail(key) // 第 3 次触发锁定
	if !lo.Locked(key) {
		t.Fatal("threshold reached should lock")
	}

	now = now.Add(2 * time.Minute) // 超过锁定窗口
	if lo.Locked(key) {
		t.Fatal("lock should expire after window")
	}
}

func TestSuccessResetsFailures(t *testing.T) {
	clock := func() time.Time { return time.Unix(1000, 0) }
	lo := NewLockout(3, time.Minute, clock)
	lo.Fail("k")
	lo.Fail("k")
	lo.Reset("k")
	lo.Fail("k")
	lo.Fail("k")
	if lo.Locked("k") {
		t.Fatal("Reset should clear prior failures")
	}
}
