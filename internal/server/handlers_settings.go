package server

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/config"
)

// settingsHandlers 提供面板级设置的 admin-only 读写。面板设置始终可用(不像模块可开关),
// 故直接挂在 server 的 RequireAuth 组里而非作为模块。
type settingsHandlers struct {
	mu       sync.Mutex
	cfg      *config.Config
	saveCfg  func(*config.Config) error                  // 注入;生产 = func(c){ return c.Save() }
	banGuard *auth.IPBanGuard                            // nil-safe
	probe    *EntryProbeGuard                            // nil-safe
	audit    func(uid *int64, action, detail, ip string) // 写审计
	clientIP func(*http.Request) string                  // 取真实来源 IP
}

// PanelSettings 是 GET 响应。绝不含 jwt_secret / db_path。
type PanelSettings struct {
	Addr                    string   `json:"addr"`
	LoginMaxAttempts        int      `json:"login_max_attempts"`
	IPBanHours              int      `json:"ip_ban_hours"`
	EntryProbeMax           int      `json:"entry_probe_max"`
	EntryProbeWindowMinutes int      `json:"entry_probe_window_minutes"`
	TrustedProxies          []string `json:"trusted_proxies"`
	EntryPath               string   `json:"entry_path"`
}

// settingsUpdate 是 PUT 请求体。指针字段区分"未提供"与"零值"。
type settingsUpdate struct {
	Addr                    *string   `json:"addr"`
	LoginMaxAttempts        *int      `json:"login_max_attempts"`
	IPBanHours              *int      `json:"ip_ban_hours"`
	EntryProbeMax           *int      `json:"entry_probe_max"`
	EntryProbeWindowMinutes *int      `json:"entry_probe_window_minutes"`
	TrustedProxies          *[]string `json:"trusted_proxies"`
	EntryPath               *string   `json:"entry_path"`
}

func (h *settingsHandlers) handleGet(w http.ResponseWriter, r *http.Request) {
	if _, role := PrincipalFromRequest(r); role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}
	c := h.cfg
	tp := c.TrustedProxies
	if tp == nil {
		tp = []string{}
	}
	writeJSON(w, http.StatusOK, PanelSettings{
		Addr:                    c.Addr,
		LoginMaxAttempts:        c.LoginMaxAttempts,
		IPBanHours:              c.IPBanHours,
		EntryProbeMax:           c.EntryProbeMax,
		EntryProbeWindowMinutes: c.EntryProbeWindowMinutes,
		TrustedProxies:          tp,
		EntryPath:               c.NormalizedEntryPath(),
	})
}

func (h *settingsHandlers) handlePut(w http.ResponseWriter, r *http.Request) {
	uid, role := PrincipalFromRequest(r)
	if role != "admin" {
		http.Error(w, "forbidden: requires admin role", http.StatusForbidden)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
	dec.DisallowUnknownFields()
	var req settingsUpdate
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	c := h.cfg
	changed := map[string]bool{}

	if req.LoginMaxAttempts != nil {
		v := *req.LoginMaxAttempts
		if v < 1 || v > 1000 {
			http.Error(w, "login_max_attempts must be in 1..1000", http.StatusBadRequest)
			return
		}
		if v != c.LoginMaxAttempts {
			changed["login_max_attempts"] = true
		}
	}
	if req.IPBanHours != nil {
		v := *req.IPBanHours
		if v < 1 || v > 8760 {
			http.Error(w, "ip_ban_hours must be in 1..8760", http.StatusBadRequest)
			return
		}
		if v != c.IPBanHours {
			changed["ip_ban_hours"] = true
		}
	}
	if req.EntryProbeMax != nil {
		v := *req.EntryProbeMax
		if v < 1 || v > 100000 {
			http.Error(w, "entry_probe_max must be in 1..100000", http.StatusBadRequest)
			return
		}
		if v != c.EntryProbeMax {
			changed["entry_probe_max"] = true
		}
	}
	if req.EntryProbeWindowMinutes != nil {
		v := *req.EntryProbeWindowMinutes
		if v < 1 || v > 1440 {
			http.Error(w, "entry_probe_window_minutes must be in 1..1440", http.StatusBadRequest)
			return
		}
		if v != c.EntryProbeWindowMinutes {
			changed["entry_probe_window_minutes"] = true
		}
	}
	if req.TrustedProxies != nil {
		if err := config.ValidateTrustedProxies(*req.TrustedProxies); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if !reflect.DeepEqual(*req.TrustedProxies, c.TrustedProxies) {
			changed["trusted_proxies"] = true
		}
	}
	var normEntryPath string
	if req.EntryPath != nil {
		norm, err := config.ValidateEntryPath(*req.EntryPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		normEntryPath = norm
		if norm != c.NormalizedEntryPath() {
			changed["entry_path"] = true
		}
	}
	if req.Addr != nil {
		if err := config.ValidateAddr(*req.Addr); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if *req.Addr != c.Addr {
			changed["addr"] = true
		}
	}

	// 危险变更(改入口路径/监听地址)须带确认头,否则一律不落盘。
	if (changed["entry_path"] || changed["addr"]) && r.Header.Get("X-Confirm-Danger") == "" {
		http.Error(w, "dangerous operation requires X-Confirm-Danger header", http.StatusPreconditionRequired)
		return
	}

	// 应用已提供的值(仅在校验全过且确认门通过后)。
	if req.LoginMaxAttempts != nil {
		c.LoginMaxAttempts = *req.LoginMaxAttempts
	}
	if req.IPBanHours != nil {
		c.IPBanHours = *req.IPBanHours
	}
	if req.EntryProbeMax != nil {
		c.EntryProbeMax = *req.EntryProbeMax
	}
	if req.EntryProbeWindowMinutes != nil {
		c.EntryProbeWindowMinutes = *req.EntryProbeWindowMinutes
	}
	if req.TrustedProxies != nil {
		c.TrustedProxies = *req.TrustedProxies
	}
	if req.EntryPath != nil {
		c.EntryPath = normEntryPath
	}
	if req.Addr != nil {
		c.Addr = *req.Addr
	}

	if err := h.saveCfg(c); err != nil {
		http.Error(w, "failed to persist settings", http.StatusInternalServerError)
		return
	}

	// 落盘成功后才热应用,避免宣称成功却未持久化。
	if h.banGuard != nil && (changed["login_max_attempts"] || changed["ip_ban_hours"]) {
		h.banGuard.SetThresholds(c.LoginMaxAttempts, time.Duration(c.IPBanHours)*time.Hour)
	}
	if h.probe != nil && (changed["entry_probe_max"] || changed["entry_probe_window_minutes"]) {
		h.probe.SetThresholds(c.EntryProbeMax, time.Duration(c.EntryProbeWindowMinutes)*time.Minute)
	}

	// 审计只记变更的字段名,绝不记其值(可能含敏感的入口路径/地址)。
	changedNames := sortedKeys(changed)
	h.audit(&uid, "panel.settings.update", strings.Join(changedNames, ","), h.clientIP(r))

	restart := []string{}
	for _, name := range changedNames {
		switch name {
		case "entry_path", "addr", "trusted_proxies":
			restart = append(restart, name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"restart_required": restart})
}

// sortedKeys 返回 m 中值为 true 的键,按固定顺序(审计/restart 列表稳定)。
func sortedKeys(m map[string]bool) []string {
	order := []string{
		"login_max_attempts", "ip_ban_hours",
		"entry_probe_max", "entry_probe_window_minutes",
		"trusted_proxies", "entry_path", "addr",
	}
	out := make([]string, 0, len(m))
	for _, k := range order {
		if m[k] {
			out = append(out, k)
		}
	}
	return out
}
