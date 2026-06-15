package module

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// moduleView 是 /api/modules 列表项:元信息 + 当前启用态 + 导航。
type moduleView struct {
	ModuleMeta
	Enabled bool      `json:"enabled"`
	Nav     []NavItem `json:"nav"`
}

// ModuleAPI 返回模块管理路由:列表对任意已认证角色开放,启用/停用要求 admin。
// principal 从请求取登录主体 (userID, role),由调用方注入以免 module 反向依赖 server。
func ModuleAPI(reg *Registry, mgr *Manager, principal func(*http.Request) (int64, string)) http.Handler {
	r := chi.NewRouter()

	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		views := make([]moduleView, 0)
		for _, m := range reg.All() {
			meta := m.Meta()
			if meta.Requires == nil {
				meta.Requires = []string{}
			}
			nav := m.Nav()
			if nav == nil {
				nav = []NavItem{}
			}
			views = append(views, moduleView{
				ModuleMeta: meta,
				Enabled:    mgr.IsEnabled(meta.ID),
				Nav:        nav,
			})
		}
		writeJSON(w, http.StatusOK, views)
	})

	r.Post("/{id}/enable", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if _, ok := reg.Get(id); !ok {
			http.NotFound(w, r)
			return
		}
		if _, role := principal(r); role != "admin" {
			http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
			return
		}
		if err := mgr.Enable(id); err != nil {
			var ve *ValidationError
			if errors.As(err, &ve) {
				http.Error(w, ve.Msg, http.StatusConflict)
			} else {
				log.Printf("module enable %q: %v", id, err)
				http.Error(w, "module operation failed", http.StatusConflict)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	r.Post("/{id}/disable", func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		if _, ok := reg.Get(id); !ok {
			http.NotFound(w, r)
			return
		}
		if _, role := principal(r); role != "admin" {
			http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
			return
		}
		if err := mgr.Disable(id); err != nil {
			var ve *ValidationError
			if errors.As(err, &ve) {
				http.Error(w, ve.Msg, http.StatusConflict)
			} else {
				log.Printf("module disable %q: %v", id, err)
				http.Error(w, "module operation failed", http.StatusConflict)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})

	return r
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
