package sitemonitor

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

// errBlockedAddr 表示探测目标 IP 命中 SSRF 黑名单(回环/私网/链路本地/元数据等)。
var errBlockedAddr = errors.New("blocked address")

// Prober 抽象单次 HTTP 探测,便于测试注入 mock(零真实网络)。
type Prober interface {
	// Probe 对 url 发一次 GET,timeout 为总超时。返回 HTTP 状态码与是否 up;
	// 连接/超时/SSRF 拦截等失败时返回 (0, false, err)。
	Probe(ctx context.Context, url string, timeout time.Duration) (statusCode int, up bool, err error)
}

// safeProber 是带 SSRF 拦截的真实探测器:在 TCP 拨号阶段拒绝任何指向内网/回环/
// 链路本地/元数据的地址,且禁止跨协议重定向。2xx/3xx 视为 up。
type safeProber struct{}

func (safeProber) Probe(ctx context.Context, rawURL string, timeout time.Duration) (int, bool, error) {
	transport := &http.Transport{
		DialContext: func(dctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(dctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, errBlockedAddr
				}
			}
			// 用已解析、已校验的首个 IP 拨号,避免解析-拨号间被换地址(TOCTOU)。
			d := &net.Dialer{Timeout: timeout}
			return d.DialContext(dctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(reqr *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			if reqr.URL.Scheme != "http" && reqr.URL.Scheme != "https" {
				return fmt.Errorf("%w: cross-protocol redirect", errBlockedAddr)
			}
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, false, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, false, err
	}
	resp.Body.Close()
	up := resp.StatusCode >= 200 && resp.StatusCode < 400
	return resp.StatusCode, up, nil
}

// isBlockedIP 判定 IP 是否属于禁止访问的网段:回环、私网(RFC1918/ULA)、
// 链路本地(含 169.254.169.254 元数据)、未指定、组播、保留。与 files 模块同策略。
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsUnspecified() || ip.IsPrivate() {
		return true
	}
	if ip.Equal(net.IPv4(169, 254, 169, 254)) {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0:
			return true
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10 (CGNAT)
			return true
		}
	}
	return false
}

// prober 是后台周期探测器:对每个 enabled 目标按各自 interval 周期 GET 探测,
// 结果落 monitor_results。由 context 驱动,Stop 取消 ctx 后干净退出。
type prober struct {
	ms    *monitorStore
	probe Prober

	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex // 保护 cancel/done(Start/Stop 可能并发)
}

func newProber(ms *monitorStore, p Prober) *prober {
	return &prober{ms: ms, probe: p}
}

// tickInterval 是调度循环的基础步进:每此间隔检查哪些目标到点该探测。
const tickInterval = 5 * time.Second

// start 起后台 goroutine 并立即返回(幂等:已在运行则忽略)。
func (p *prober) start(ctx context.Context) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cancel != nil {
		return
	}
	cctx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	go p.run(cctx, p.done)
}

// stop 取消 ctx 并等待 run 退出(无 goroutine 泄漏)。
func (p *prober) stop() {
	p.mu.Lock()
	cancel, done := p.cancel, p.done
	p.cancel, p.done = nil, nil
	p.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// run 是调度循环:每 tickInterval 扫一遍 enabled 目标,到点(距上次探测 >= interval)
// 就探测。ctx 取消即退出。
func (p *prober) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	lastProbe := make(map[int64]time.Time)
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	for {
		p.sweep(ctx, lastProbe)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// sweep 探测所有到点的 enabled 目标。lastProbe 记录每目标上次探测时刻。
func (p *prober) sweep(ctx context.Context, lastProbe map[int64]time.Time) {
	targets, err := p.ms.listTargets()
	if err != nil {
		log.Printf("sitemonitor: list targets for probe: %v", err)
		return
	}
	now := time.Now()
	for _, t := range targets {
		if !t.Enabled {
			continue
		}
		if last, ok := lastProbe[t.ID]; ok && now.Sub(last) < time.Duration(t.IntervalSec)*time.Second {
			continue
		}
		if ctx.Err() != nil {
			return
		}
		lastProbe[t.ID] = now
		p.probeOne(ctx, t)
	}
}

// probeOne 探测单个目标并落盘结果。
func (p *prober) probeOne(ctx context.Context, t Target) {
	timeout := time.Duration(t.TimeoutSec) * time.Second
	started := time.Now()
	code, up, err := p.probe.Probe(ctx, t.URL, timeout)
	res := Result{
		TargetID:   t.ID,
		CheckedAt:  time.Now().Unix(),
		Up:         up,
		StatusCode: code,
		LatencyMS:  time.Since(started).Milliseconds(),
	}
	if err != nil {
		res.Err = err.Error()
	}
	if serr := p.ms.insertResult(res); serr != nil {
		log.Printf("sitemonitor: save probe result for target %d: %v", t.ID, serr)
	}
}
