package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func auditTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	u, _ := s.CreateUser("admin", "h", "admin")
	if err := s.WriteAudit(&u.ID, "login.success", "", "1.2.3.4"); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	if err := s.WriteAudit(nil, "panel.settings.update", "addr", "5.6.7.8"); err != nil {
		t.Fatalf("write audit: %v", err)
	}
	return s
}

func TestAuditListAdmin(t *testing.T) {
	s := auditTestStore(t)
	h := &auditHandlers{list: s.ListAudit}
	r := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/audit", nil), 1, "admin")
	w := httptest.NewRecorder()
	h.handleList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET admin code = %d, want 200", w.Code)
	}

	var resp struct {
		Entries []store.AuditEntry `json:"entries"`
		Total   int                `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v (%s)", err, w.Body.String())
	}
	if resp.Total != 2 {
		t.Fatalf("total = %d, want 2", resp.Total)
	}
	if len(resp.Entries) != 2 {
		t.Fatalf("entries len = %d, want 2", len(resp.Entries))
	}
	// 字段形状:每条含 ts/user_id/action/detail/source_ip。
	for _, key := range []string{`"ts"`, `"user_id"`, `"action"`, `"detail"`, `"source_ip"`} {
		if !containsKey(w.Body.String(), key) {
			t.Errorf("response missing key %s: %s", key, w.Body.String())
		}
	}
}

func TestAuditListNonAdmin(t *testing.T) {
	s := auditTestStore(t)
	h := &auditHandlers{list: s.ListAudit}
	r := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/audit", nil), 2, "operator")
	w := httptest.NewRecorder()
	h.handleList(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("GET non-admin code = %d, want 403", w.Code)
	}
}

func TestAuditListActionFilter(t *testing.T) {
	s := auditTestStore(t)
	h := &auditHandlers{list: s.ListAudit}
	r := withPrincipal(httptest.NewRequest(http.MethodGet, "/api/audit?action=login.", nil), 1, "admin")
	w := httptest.NewRecorder()
	h.handleList(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("filtered code = %d, want 200", w.Code)
	}
	var resp struct {
		Entries []store.AuditEntry `json:"entries"`
		Total   int                `json:"total"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if resp.Total != 1 || len(resp.Entries) != 1 {
		t.Fatalf("filtered total/len = %d/%d, want 1/1", resp.Total, len(resp.Entries))
	}
	if resp.Entries[0].Action != "login.success" {
		t.Fatalf("filtered action = %q", resp.Entries[0].Action)
	}
}

func containsKey(body, key string) bool {
	for i := 0; i+len(key) <= len(body); i++ {
		if body[i:i+len(key)] == key {
			return true
		}
	}
	return false
}
