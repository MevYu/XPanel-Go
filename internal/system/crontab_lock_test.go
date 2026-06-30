package system

import (
	"path/filepath"
	"testing"
	"time"
)

func TestLockCrontabExclusive(t *testing.T) {
	lockPath := filepath.Join(t.TempDir(), "lock")
	oldPath, oldTO := CrontabLockPath, CrontabLockTimeout
	CrontabLockPath = func() string { return lockPath }
	CrontabLockTimeout = 200 * time.Millisecond
	t.Cleanup(func() { CrontabLockPath, CrontabLockTimeout = oldPath, oldTO })

	release, err := LockCrontab()
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}

	// 持锁期间再取应轮询至超时后失败,且不返回 release。
	start := time.Now()
	r2, err := LockCrontab()
	if err == nil {
		r2()
		t.Fatal("second acquire succeeded while lock held; want timeout error")
	}
	if waited := time.Since(start); waited < 150*time.Millisecond {
		t.Fatalf("second acquire returned after %v; want ~timeout (>=150ms)", waited)
	}

	release() // 释放后应可再次获取。
	r3, err := LockCrontab()
	if err != nil {
		t.Fatalf("re-acquire after release: %v", err)
	}
	r3()
}
