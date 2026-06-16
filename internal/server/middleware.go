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

// clientIP 取请求来源 IP(RemoteAddr,不信任任何代理头,与限速/封禁一致)。
func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// IPBanMiddleware 在最前面拦掉被封禁 IP 的全部请求,返回 429。
// banned 报告该 IP 是否在封禁期内(由 auth.IPBanGuard 提供)。
func IPBanMiddleware(banned func(ip string) bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if banned(clientIP(r)) {
				http.Error(w, "forbidden", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// EntryGate 隐藏面板入口:非白名单前缀且不在 entryPath 下的请求一律 404(不暴露面板)。
// 白名单:/api/* (含认证)、/s/*(公开模块)、/healthz、/assets/*(静态资源)。
// entryPath 及其子路径放行给 SPA handler。
func EntryGate(entryPath string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if isAllowedPrefix(p) || underEntry(p, entryPath) {
				next.ServeHTTP(w, r)
				return
			}
			http.NotFound(w, r)
		})
	}
}

func isAllowedPrefix(p string) bool {
	return p == "/healthz" ||
		p == "/api" || strings.HasPrefix(p, "/api/") ||
		p == "/s" || strings.HasPrefix(p, "/s/") ||
		p == "/assets" || strings.HasPrefix(p, "/assets/")
}

// underEntry 判断 p 是否等于 entryPath 或在其子路径下。
func underEntry(p, entryPath string) bool {
	if entryPath == "/" {
		return true
	}
	return p == entryPath || strings.HasPrefix(p, entryPath+"/")
}

// RateLimiter:每 IP 一个令牌桶,容量 burst,每秒回补 1 个令牌。
type RateLimiter struct {
	burst     float64
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
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

	// 空闲淘汰阈值:桶回补到满需 burst 秒,陈旧条目与全新桶等价,可安全删除。
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
		if !rl.allow(clientIP(r)) {
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

// PrincipalFromRequest 取出 RequireAuth 放进 context 的登录主体。未认证返回 (0, "")。
func PrincipalFromRequest(r *http.Request) (int64, string) {
	p, ok := r.Context().Value(claimsKey).(principal)
	if !ok {
		return 0, ""
	}
	return p.userID, p.role
}
