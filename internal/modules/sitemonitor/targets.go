package sitemonitor

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
)

// handleListTargets 返回所有目标 + 各自最近探测摘要(状态/响应时间/状态码/最近检测时间/可用率)。
// 只读:任意已认证角色可访问。
func (m *Module) handleListTargets(w http.ResponseWriter, _ *http.Request) {
	targets, err := m.ms.listTargets()
	if err != nil {
		serverError(w, "list targets", err)
		return
	}
	views := make([]TargetView, 0, len(targets))
	for _, t := range targets {
		v, err := m.ms.targetView(t)
		if err != nil {
			serverError(w, "target view", err)
			return
		}
		views = append(views, v)
	}
	writeJSON(w, http.StatusOK, views)
}

// handleCreateTarget 新建探测目标。写:operator/admin(由 requireWrite 把守)+ 审计。
func (m *Module) handleCreateTarget(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	var in targetInput
	if !decode(w, r, &in) {
		return
	}
	if err := in.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := m.ms.createTarget(in)
	if err != nil {
		serverError(w, "create target", err)
		return
	}
	m.deps.Audit(&uid, "sitemonitor.target.create", t.Name+" "+t.URL, m.clientIP(r))
	writeJSON(w, http.StatusCreated, t)
}

// handleUpdateTarget 全量更新目标。写:operator/admin + 审计。
func (m *Module) handleUpdateTarget(w http.ResponseWriter, r *http.Request) {
	uid, _ := m.deps.Principal(r)
	id, ok := targetID(w, r)
	if !ok {
		return
	}
	var in targetInput
	if !decode(w, r, &in) {
		return
	}
	if err := in.validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	t, err := m.ms.updateTarget(id, in)
	if errors.Is(err, errTargetNotFound) {
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "update target", err)
		return
	}
	m.deps.Audit(&uid, "sitemonitor.target.update", t.Name+" "+t.URL, m.clientIP(r))
	writeJSON(w, http.StatusOK, t)
}

// handleDeleteTarget 删除目标及其探测历史。危险操作:admin + X-Confirm-Danger + 审计。
func (m *Module) handleDeleteTarget(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Confirm-Danger") == "" {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}
	uid, ok := m.requireAdmin(w, r)
	if !ok {
		return
	}
	id, ok := targetID(w, r)
	if !ok {
		return
	}
	err := m.ms.deleteTarget(id)
	if errors.Is(err, errTargetNotFound) {
		http.Error(w, "target not found", http.StatusNotFound)
		return
	}
	if err != nil {
		serverError(w, "delete target", err)
		return
	}
	m.deps.Audit(&uid, "sitemonitor.target.delete", strconv.FormatInt(id, 10), m.clientIP(r))
	w.WriteHeader(http.StatusNoContent)
}

// targetID 解析路径里的 {id};非法时写 400 并返回 ok=false。
func targetID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(chi.URLParamFromCtx(r.Context(), "id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "invalid target id", http.StatusBadRequest)
		return 0, false
	}
	return id, true
}
