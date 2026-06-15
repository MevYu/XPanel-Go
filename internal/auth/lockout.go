package auth

import (
	"sync"
	"time"
)

// Lockout 按 key(建议 "username@ip")限制连续失败。内存态,进程重启即清零(可接受)。
type Lockout struct {
	threshold int
	window    time.Duration
	now       func() time.Time

	mu      sync.Mutex
	entries map[string]*lockEntry
}

type lockEntry struct {
	failures int
	lockedAt time.Time
}

func NewLockout(threshold int, window time.Duration, now func() time.Time) *Lockout {
	return &Lockout{
		threshold: threshold,
		window:    window,
		now:       now,
		entries:   make(map[string]*lockEntry),
	}
}

func (l *Lockout) Locked(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil || e.failures < l.threshold {
		return false
	}
	if l.now().Sub(e.lockedAt) >= l.window {
		delete(l.entries, key) // 窗口过期,解锁
		return false
	}
	return true
}

func (l *Lockout) Fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		e = &lockEntry{}
		l.entries[key] = e
	}
	e.failures++
	if e.failures >= l.threshold {
		e.lockedAt = l.now()
	}
}

func (l *Lockout) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}
