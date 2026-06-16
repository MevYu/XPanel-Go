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

// remoteIP 取 RemoteAddr 的纯 IP(去端口)。解析失败回退原值。
func remoteIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// ExtractClientIP 是全局唯一的真实客户端 IP 提取逻辑,供中间件、登录 handler、
// 各模块审计共用。trusted 为受信反代网段(来自 config.TrustedProxies)。
//
// 规则:RemoteAddr 不在 trusted 内 → 直接用 RemoteAddr,忽略 XFF(防伪造);
// 在 trusted 内 → 从右往左跳过 XFF 中所有受信 IP,返回首个非受信 IP;
// XFF 全受信/为空时回退 X-Real-IP,再回退 RemoteAddr。
// trusted 为空 → 永远返回 RemoteAddr(直连部署,行为与旧实现一致)。
func ExtractClientIP(r *http.Request, trusted []*net.IPNet) string {
	remote := remoteIP(r)
	if len(trusted) == 0 || !ipInNets(remote, trusted) {
		return remote
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(parts[i])
			if ip == "" {
				continue
			}
			if !ipInNets(ip, trusted) {
				return ip
			}
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		return xr
	}
	return remote
}

// ipInNets 报告 ip 是否落在任一网段内。无法解析的 ip 视为不在内。
func ipInNets(ip string, nets []*net.IPNet) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// clientIPFunc 返回绑定了受信网段的提取器,用于注入中间件/模块 Deps。
func clientIPFunc(trusted []*net.IPNet) func(*http.Request) string {
	return func(r *http.Request) string { return ExtractClientIP(r, trusted) }
}

// IPBanMiddleware 在最前面拦掉被封禁 IP 的全部请求,返回 429。
// banned 报告该 IP 是否在封禁期内(由 auth.IPBanGuard 提供)。
// clientIP 提取真实客户端 IP(受信代理感知),封禁 key 与登录侧一致。
func IPBanMiddleware(banned func(ip string) bool, clientIP func(*http.Request) string) func(http.Handler) http.Handler {
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
// 白名单:/api/* (含认证)、/s/*(公开模块)、/healthz、/assets/*(静态资源),
// 以及 fileExists 报告为嵌入 FS 中真实存在文件的路径(如 /favicon.svg、/robots.txt)。
// entryPath 及其子路径放行给 SPA handler。
// fileExists(非 nil 时)放行真实静态文件,使正常用户加载页面资源不被 404/计探测。
// loggedIn(非 nil 时)报告请求是否携带有效登录态 cookie:命中未知路径的已登录用户
// 302 重定向回入口首页(entryPath+"/"),不计探测、不封禁。
// onProbe(非 nil 时)在每次 404(入口探测命中)时以请求为参回调,用于探测计数/封禁。
func EntryGate(entryPath string, fileExists func(string) bool, loggedIn func(*http.Request) bool, onProbe func(*http.Request)) func(http.Handler) http.Handler {
	redirectTo := entryPath + "/"
	if entryPath == "/" {
		redirectTo = "/"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := r.URL.Path
			if isAllowedPrefix(p) || underEntry(p, entryPath) || (fileExists != nil && fileExists(p)) {
				next.ServeHTTP(w, r)
				return
			}
			// 已登录用户(浏览器跳转/刷新带 SameSite=Lax cookie)回入口首页,不算扫描探测。
			if loggedIn != nil && loggedIn(r) {
				http.Redirect(w, r, redirectTo, http.StatusFound)
				return
			}
			if onProbe != nil {
				onProbe(r)
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
	clientIP  func(*http.Request) string
	mu        sync.Mutex
	buckets   map[string]*bucket
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter 用 RemoteAddr 作 key(不感知代理)。受信代理部署用 NewRateLimiterWithClientIP。
func NewRateLimiter(burst int) *RateLimiter {
	return &RateLimiter{burst: float64(burst), clientIP: remoteIP, buckets: make(map[string]*bucket)}
}

// NewRateLimiterWithClientIP 用注入的提取器取限速 key(受信代理感知)。
func NewRateLimiterWithClientIP(burst int, clientIP func(*http.Request) string) *RateLimiter {
	return &RateLimiter{burst: float64(burst), clientIP: clientIP, buckets: make(map[string]*bucket)}
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
		if !rl.allow(rl.clientIP(r)) {
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

// hasValidBearer 报告请求是否携带可被 parse 成功解析的 Bearer token。
// 用于探测计数排除:已登录用户命中未知路径不算入口探测,避免正常用户自封。
func hasValidBearer(r *http.Request, parse func(token string) (int64, string, error)) bool {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Bearer ") {
		return false
	}
	_, _, err := parse(strings.TrimPrefix(h, "Bearer "))
	return err == nil
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
