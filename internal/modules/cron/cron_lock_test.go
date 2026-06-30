package cron

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// TestSyncRefusesWriteWhenHostLockHeld 证明 syncCrontab 在 RMW 外获取了 host 锁:
// 外部持锁时 sync 应超时失败且不写 crontab(宁失败不丢更新),释放后再 sync 成功写入。
func TestSyncRefusesWriteWhenHostLockHeld(t *testing.T) {
	fakeCrontab(t) // 同时把 host 锁重定向到临时文件
	oldTO := system.CrontabLockTimeout
	system.CrontabLockTimeout = 150 * time.Millisecond
	t.Cleanup(func() { system.CrontabLockTimeout = oldTO })

	m, _, _ := newTestModuleSeed(t, "operator", "/data/inst-x/xpanel.db")

	// 外部抢占 host 锁,模拟另一进程正在改 crontab。
	release, err := system.LockCrontab()
	if err != nil {
		t.Fatalf("hold host lock: %v", err)
	}

	if err := m.syncCrontab(); err == nil {
		release()
		t.Fatal("syncCrontab succeeded while host lock held; want timeout error")
	}
	if ct, _ := readSpool(m); strings.Contains(ct, "managed:"+m.key) {
		release()
		t.Fatalf("syncCrontab wrote despite contention:\n%s", ct)
	}

	release() // 释放后 sync 应成功并写入本实例块。
	if err := m.syncCrontab(); err != nil {
		t.Fatalf("syncCrontab after release: %v", err)
	}
	if ct, _ := readSpool(m); !strings.Contains(ct, "managed:"+m.key) {
		t.Fatalf("syncCrontab did not write managed block after lock free:\n%s", ct)
	}
}

// TestSyncConcurrentNoLostUpdate 两实例并发 sync 同一份 crontab,host 锁串行化后两块都在。
func TestSyncConcurrentNoLostUpdate(t *testing.T) {
	fakeCrontab(t)
	_, hA, _ := newTestModuleSeed(t, "operator", "/data/inst-a/xpanel.db")
	_, hB, _ := newTestModuleSeed(t, "operator", "/data/inst-b/xpanel.db")

	post := func(wg *sync.WaitGroup, h http.Handler, body string) {
		defer wg.Done()
		req := httptest.NewRequest(http.MethodPost, "/jobs", strings.NewReader(body))
		h.ServeHTTP(httptest.NewRecorder(), req)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go post(&wg, hA, `{"expr":"0 3 * * *","command":"/a/job.sh"}`)
	go post(&wg, hB, `{"expr":"0 4 * * *","command":"/b/job.sh"}`)
	wg.Wait()

	ct, _ := readSpool(nil)
	if !strings.Contains(ct, "/a/job.sh") {
		t.Errorf("instance A's block lost under concurrent sync:\n%s", ct)
	}
	if !strings.Contains(ct, "/b/job.sh") {
		t.Errorf("instance B's block lost under concurrent sync:\n%s", ct)
	}
}
