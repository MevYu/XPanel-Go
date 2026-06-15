package module

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Mount 把每个注册模块的路由挂在 /api/m/<id>/ 下,外包一层启用门:
// 模块未启用时返回 404,不进入模块 handler。启用/停用只翻转 Manager 标志,不改路由树。
func Mount(root chi.Router, reg *Registry, mgr *Manager) {
	for _, m := range reg.All() {
		id := m.Meta().ID
		sub := chi.NewRouter()
		m.Routes(sub)
		root.Mount("/api/m/"+id, gate(id, mgr, sub))
	}
}

func gate(id string, mgr *Manager, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !mgr.IsEnabled(id) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
