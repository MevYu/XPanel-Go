package loadbalancer

import (
	"context"
	"net"
	"sync"
	"time"
)

// probeTimeout 是单个后端探测的超时。固定值,避免拖慢只读端点。
const probeTimeout = 3 * time.Second

// Prober 抽象对单个后端的存活探测,便于单测注入 mock(测试零真实网络)。
// 实现约定:addr 来自已存配置(host:port),绝不接受任意用户输入,防 SSRF。
type Prober interface {
	// Probe 在 timeout 内尝试连通 addr。可达返回 nil,否则返回错误。
	Probe(ctx context.Context, addr string, timeout time.Duration) error
}

// tcpProber 用 TCP 拨号判存活:能建连即视为 up。
type tcpProber struct{}

func (tcpProber) Probe(ctx context.Context, addr string, timeout time.Duration) error {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(cctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// BackendHealth 是单个后端的探测结果。ResponseMs 仅在 Up 时有意义。
type BackendHealth struct {
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Up         bool   `json:"up"`
	ResponseMs int64  `json:"response_ms"`
	Error      string `json:"error,omitempty"`
}

// GroupHealth 是一个均衡组所有后端的健康聚合。
type GroupHealth struct {
	GroupID  int64           `json:"group_id"`
	Name     string          `json:"name"`
	Backends []BackendHealth `json:"backends"`
}

// probeBackends 并发探测一组后端,按入参顺序返回结果。p 不可为 nil。
func probeBackends(ctx context.Context, p Prober, backends []Backend) []BackendHealth {
	results := make([]BackendHealth, len(backends))
	var wg sync.WaitGroup
	for i, b := range backends {
		wg.Add(1)
		go func(i int, b Backend) {
			defer wg.Done()
			start := time.Now()
			err := p.Probe(ctx, b.Addr(), probeTimeout)
			h := BackendHealth{Host: b.Host, Port: b.Port}
			if err == nil {
				h.Up = true
				h.ResponseMs = time.Since(start).Milliseconds()
			} else {
				h.Error = err.Error()
			}
			results[i] = h
		}(i, b)
	}
	wg.Wait()
	return results
}
