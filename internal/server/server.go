package server

import (
	"net"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
	webui "github.com/MevYu/XPanel-Go/web"
)

// New 装配整个 HTTP handler:中间件链 + 认证路由 + 受保护示例路由。
func New(svc *auth.Service, jwt *auth.JWTManager) http.Handler {
	r := chi.NewRouter()
	r.Use(SecurityHeaders)
	r.Use(NewRateLimiter(60).Middleware) // 每 IP 60 burst

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ah := &authHandlers{svc: svc, clientIP: remoteIP}
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/login", ah.login)
		r.Post("/refresh", ah.refresh)
		r.Post("/logout", ah.logout)
	})

	parse := func(token string) (int64, string, error) {
		c, err := jwt.Parse(token)
		if err != nil {
			return 0, "", err
		}
		return c.UserID, c.Role, nil
	}
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(parse))
		r.Get("/api/me", func(w http.ResponseWriter, r *http.Request) {
			p := r.Context().Value(claimsKey).(principal)
			writeJSON(w, http.StatusOK, map[string]any{"user_id": p.userID, "role": p.role})
		})
	})

	return r
}

// LoginTOTPVerifier 在登录密码通过后校验该用户的 2FA。enabled=用户是否启用 2FA,
// ok=code 是否通过。宿主用 users.VerifyLoginTOTP 适配并注入,避免 server 依赖其内部。
type LoginTOTPVerifier func(userID int64, code string) (enabled, ok bool, err error)

// NewWithModules 在基础路由上接入模块系统:模块管理 API + 各模块路由(带启用门)。
// totp 为登录时的 2FA 校验器;传 nil 则不启用登录 2FA 门。
// ipBanned 报告来源 IP 是否被封禁(传 nil 则不启用 IP 封禁门)。
// trusted 为受信反代网段(来自 config.TrustedProxies);空=只信 RemoteAddr、忽略 XFF。
// entryPath 为隐藏面板入口路径;SPA 只在此路径下提供,其余非 API/静态请求返回 404。
// probe 守卫(非 nil 时)记录入口探测命中,超阈值经其内部封禁该 IP。
func NewWithModules(svc *auth.Service, jwt *auth.JWTManager, reg *module.Registry, mgr *module.Manager, totp LoginTOTPVerifier, ipBanned func(ip string) bool, trusted []*net.IPNet, entryPath string, probe *EntryProbeGuard) http.Handler {
	clientIP := clientIPFunc(trusted)
	r := chi.NewRouter()
	if ipBanned != nil {
		r.Use(IPBanMiddleware(ipBanned, clientIP)) // 最前面:被封 IP 的全部请求直接拒
	}
	parse := func(token string) (int64, string, error) {
		c, err := jwt.Parse(token)
		if err != nil {
			return 0, "", err
		}
		return c.UserID, c.Role, nil
	}

	var onProbe func(*http.Request)
	if probe != nil {
		// 带有效 Bearer token 的请求是已登录用户,命中未知路径不计探测(不自封)。
		onProbe = func(req *http.Request) {
			if hasValidBearer(req, parse) {
				return
			}
			probe.Probe(clientIP(req))
		}
	}
	// webui.FileExists 放行嵌入 FS 中真实存在的静态文件(favicon 等),它们不进 404/探测分支。
	r.Use(EntryGate(entryPath, webui.FileExists, onProbe)) // IPBanMiddleware 之后:未封 IP 记探测、超阈值触发封禁
	r.Use(SecurityHeaders)
	r.Use(NewRateLimiterWithClientIP(60, clientIP).Middleware)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ah := &authHandlers{svc: svc, totp: loginTOTPVerifier(totp), clientIP: clientIP}
	r.Route("/api/auth", func(r chi.Router) {
		r.Post("/login", ah.login)
		r.Post("/refresh", ah.refresh)
		r.Post("/logout", ah.logout)
	})

	// 公开模块路由(文件外链、WS-ticket 端点)挂在 RequireAuth 之外,模块自鉴权。
	module.MountPublic(r, reg, mgr)

	// 模块管理 API 与模块路由都需要登录;模块路由再各自做 RBAC。
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(parse))
		r.Mount("/api/modules", module.ModuleAPI(reg, mgr, PrincipalFromRequest))
		module.Mount(r, reg, mgr)
	})

	// catch-all:非 API/公开路由交给 SPA(静态资源或 index.html 回退)。
	// EntryGate 已确保只有入口路径与 /assets/* 能到这;SPA 注入 entryPath 作为 basename。
	r.NotFound(webui.HandlerWithBase(entryPath).ServeHTTP)

	return r
}
