package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/auth"
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
