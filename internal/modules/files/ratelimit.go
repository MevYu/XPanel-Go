package files

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// rateLimiter 是公开端点的独立每-IP 令牌桶(与面板限速分离,更严)。
// 每秒回补 1 个令牌,容量 burst。
type rateLimiter struct {
	burst     float64
	mu        sync.Mutex
	buckets   map[string]*rateBucket
	lastSweep time.Time
}

type rateBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(burst int) *rateLimiter {
	return &rateLimiter{burst: float64(burst), buckets: make(map[string]*rateBucket)}
}

func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()

	ttl := time.Duration(rl.burst) * time.Second
	if ttl < time.Minute {
		ttl = time.Minute
	}
	if now.Sub(rl.lastSweep) >= ttl {
		for k, v := range rl.buckets {
			if now.Sub(v.last) >= ttl {
				delete(rl.buckets, k)
			}
		}
		rl.lastSweep = now
	}

	b := rl.buckets[ip]
	if b == nil {
		rl.buckets[ip] = &rateBucket{tokens: rl.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds()
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			ip = r.RemoteAddr
		}
		if !rl.allow(ip) {
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}
