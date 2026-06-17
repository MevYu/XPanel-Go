package server

import (
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

	ah := &authHandlers{svc: svc}
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

// LoginRecorder 在登录成功后记录该用户最近登录时间。宿主用 users.RecordLogin 适配并注入。
type LoginRecorder func(userID int64)

// NewWithModules 在基础路由上接入模块系统:模块管理 API + 各模块路由(带启用门)。
// totp 为登录时的 2FA 校验器;传 nil 则不启用登录 2FA 门。
// recordLogin 登录成功后记录最近登录时间;传 nil 则不记录。
func NewWithModules(svc *auth.Service, jwt *auth.JWTManager, reg *module.Registry, mgr *module.Manager, totp LoginTOTPVerifier, recordLogin LoginRecorder) http.Handler {
	r := chi.NewRouter()
	r.Use(SecurityHeaders)
	r.Use(NewRateLimiter(60).Middleware)

	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	ah := &authHandlers{svc: svc, totp: loginTOTPVerifier(totp), recordLogin: recordLogin}
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

	// 公开模块路由(文件外链、WS-ticket 端点)挂在 RequireAuth 之外,模块自鉴权。
	module.MountPublic(r, reg, mgr)

	// 模块管理 API 与模块路由都需要登录;模块路由再各自做 RBAC。
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(parse))
		r.Mount("/api/modules", module.ModuleAPI(reg, mgr, PrincipalFromRequest))
		module.Mount(r, reg, mgr)
	})

	// catch-all:非 API/公开路由交给 SPA(静态资源或 index.html 回退)。
	// 中间件链(SecurityHeaders 等)对 NotFound 同样生效。
	r.NotFound(webui.Handler().ServeHTTP)

	return r
}
