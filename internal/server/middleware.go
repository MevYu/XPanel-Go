package server

import (
	"context"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SecurityHeaders 给所有响应加固定安全头。CSP 禁内联脚本,前端需用打包后的 JS。
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

// RateLimiter:每 IP 一个令牌桶,容量 burst,每秒回补 1 个令牌。
type RateLimiter struct {
	burst   float64
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func NewRateLimiter(burst int) *RateLimiter {
	return &RateLimiter{burst: float64(burst), buckets: make(map[string]*bucket)}
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	b := rl.buckets[ip]
	if b == nil {
		rl.buckets[ip] = &bucket{tokens: rl.burst - 1, last: now}
		return true
	}
	b.tokens += now.Sub(b.last).Seconds() // 每秒 +1
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

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
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

type ctxKey string

const claimsKey ctxKey = "claims"

// RequireAuth 校验 Bearer token,通过则把 principal 放进 context。
// 为避免 server 包反向依赖,接受一个 parse 函数。
func RequireAuth(parse func(token string) (int64, string, error)) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			uid, role, err := parse(strings.TrimPrefix(h, "Bearer "))
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), claimsKey, principal{uid, role})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

type principal struct {
	userID int64
	role   string
}
