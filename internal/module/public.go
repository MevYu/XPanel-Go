package module

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// PublicRouter:模块声明一组挂在面板认证之外的公开路由(如文件外链、WS-ticket 端点,自鉴权)。
type PublicRouter interface {
	PublicPrefix() string // 如 "/s" 或 "/api/m/terminal/ws"
	PublicRoutes() http.Handler
}

// MountPublic 把实现 PublicRouter 的模块的公开路由挂在其 PublicPrefix() 下,
// 外包一层启用门:模块停用时返回 404,不进入模块 handler(与 Mount 一致)。
// 这些路由由调用方挂在 RequireAuth 之外,模块靠自身机制(token/ticket)鉴权。
func MountPublic(root chi.Router, reg *Registry, mgr *Manager) {
	for _, m := range reg.All() {
		pr, ok := m.(PublicRouter)
		if !ok {
			continue
		}
		root.Mount(pr.PublicPrefix(), gate(m.Meta().ID, mgr, pr.PublicRoutes()))
	}
}
