package server

import (
	"net/http"
	"strconv"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// auditHandlers 提供面板审计日志的 admin-only 只读视图。审计始终可用(非模块),
// 故直接挂在 server 的 RequireAuth 组里,与面板设置端点并列。
type auditHandlers struct {
	list func(limit, offset int, action string) ([]store.AuditEntry, int, error)
}

// handleList 处理 GET /api/audit?limit=&offset=&action=。
// 默认 limit=50;limit/offset 的钳制由 store.ListAudit 负责。
func (h *auditHandlers) handleList(w http.ResponseWriter, r *http.Request) {
	if _, role := PrincipalFromRequest(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}

	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			limit = n
		}
	}
	offset := 0
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			offset = n
		}
	}
	action := r.URL.Query().Get("action")

	entries, total, err := h.list(limit, offset, action)
	if err != nil {
		http.Error(w, "failed to read audit log", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries, "total": total})
}
