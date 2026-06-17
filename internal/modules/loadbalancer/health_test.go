package loadbalancer

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// mockProber 按 addr 返回预设结果,测试零真实网络。未列出的 addr 默认 up。
// probeBackends 并发调用 Probe,故 calls 需加锁。
type mockProber struct {
	down  map[string]error // addr -> 失败错误
	delay time.Duration    // 模拟响应耗时(影响 response_ms)
	mu    sync.Mutex
	calls map[string]int
}

func newMockProber() *mockProber {
	return &mockProber{down: map[string]error{}, calls: map[string]int{}}
}

func (p *mockProber) Probe(_ context.Context, addr string, _ time.Duration) error {
	p.mu.Lock()
	p.calls[addr]++
	p.mu.Unlock()
	if p.delay > 0 {
		time.Sleep(p.delay)
	}
	if err, ok := p.down[addr]; ok {
		return err
	}
	return nil
}

func TestProbeBackendsAggregatesUpDown(t *testing.T) {
	p := newMockProber()
	p.down["10.0.0.2:8080"] = errors.New("connection refused")
	backends := []Backend{
		{Host: "10.0.0.1", Port: 8080},
		{Host: "10.0.0.2", Port: 8080},
	}
	got := probeBackends(context.Background(), p, backends)
	if len(got) != 2 {
		t.Fatalf("want 2 results, got %d", len(got))
	}
	// 结果顺序须与入参一致。
	if got[0].Host != "10.0.0.1" || !got[0].Up {
		t.Errorf("backend 0 should be up: %+v", got[0])
	}
	if got[0].Error != "" {
		t.Errorf("up backend must have no error: %+v", got[0])
	}
	if got[1].Host != "10.0.0.2" || got[1].Up {
		t.Errorf("backend 1 should be down: %+v", got[1])
	}
	if got[1].Error != "connection refused" {
		t.Errorf("down backend must carry error, got %q", got[1].Error)
	}
}

func TestProbeBackendsRecordsResponseTime(t *testing.T) {
	p := newMockProber()
	p.delay = 15 * time.Millisecond
	got := probeBackends(context.Background(), p, []Backend{{Host: "10.0.0.1", Port: 80}})
	if !got[0].Up {
		t.Fatalf("backend should be up: %+v", got[0])
	}
	if got[0].ResponseMs < 10 {
		t.Errorf("response_ms should reflect probe latency, got %d", got[0].ResponseMs)
	}
}

func TestHealthEndpointReturnsPerBackendStatus(t *testing.T) {
	p := newMockProber()
	p.down["10.0.0.2:8080"] = errors.New("dial timeout")
	m, _ := newTestModule(t, "operator", newMockNginx())
	m.prober = p
	id := seedGroup(t, m)

	rec := do(m, "GET", "/groups/"+itoa(id)+"/health", nil, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("health = %d (%s)", rec.Code, rec.Body.String())
	}
	var gh GroupHealth
	if err := json.Unmarshal(rec.Body.Bytes(), &gh); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gh.GroupID != id || gh.Name != "web" {
		t.Errorf("unexpected group meta: %+v", gh)
	}
	if len(gh.Backends) != 2 {
		t.Fatalf("want 2 backends, got %d", len(gh.Backends))
	}
	if !gh.Backends[0].Up {
		t.Errorf("backend 0 should be up: %+v", gh.Backends[0])
	}
	if gh.Backends[1].Up || gh.Backends[1].Error == "" {
		t.Errorf("backend 1 should be down with error: %+v", gh.Backends[1])
	}
	// 只探测已存配置里的地址,绝不接受任意输入。
	if p.calls["10.0.0.1:8080"] != 1 || p.calls["10.0.0.2:8080"] != 1 {
		t.Errorf("must probe exactly the stored backends, calls=%v", p.calls)
	}
}

func TestHealthEndpointGroupNotFound(t *testing.T) {
	m, _ := newTestModule(t, "operator", newMockNginx())
	m.prober = newMockProber()
	rec := do(m, "GET", "/groups/999/health", nil, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing group health should 404, got %d", rec.Code)
	}
}
