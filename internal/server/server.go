package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/module"
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

// NewWithModules 在基础路由上接入模块系统:模块管理 API + 各模块路由(带启用门)。
func NewWithModules(svc *auth.Service, jwt *auth.JWTManager, reg *module.Registry, mgr *module.Manager) http.Handler {
	r := chi.NewRouter()
	r.Use(SecurityHeaders)
	r.Use(NewRateLimiter(60).Middleware)

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

	// 模块管理 API 与模块路由都需要登录;模块路由再各自做 RBAC。
	r.Group(func(r chi.Router) {
		r.Use(RequireAuth(parse))
		r.Mount("/api/modules", module.ModuleAPI(reg, mgr))
		module.Mount(r, reg, mgr)
	})

	return r
}
