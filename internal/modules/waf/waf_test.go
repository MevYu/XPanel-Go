package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestModule(t *testing.T, role string, audited *int) (*Module, chi.Router) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	m := New(st, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	r := chi.NewRouter()
	m.Routes(r)
	return m, r
}

func do(r chi.Router, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchableSecurity(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	meta := m.Meta()
	if meta.ID != "waf" || meta.AlwaysOn {
		t.Errorf("waf must be id=waf, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "安全" {
		t.Errorf("category must be 安全, got %q", meta.Category)
	}
}

func TestNav(t *testing.T) {
	m, _ := newTestModule(t, "admin", new(int))
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/waf" {
		t.Errorf("nav must expose /waf, got %+v", nav)
	}
}

func TestWriteEndpointsRequireAdmin(t *testing.T) {
	writes := []struct {
		method, path, body string
	}{
		{"POST", "/ip", `{"action":"deny","cidr":"1.2.3.4"}`},
		{"DELETE", "/ip/1", ""},
		{"POST", "/match", `{"target":"uri","pattern":"x","action":"block"}`},
		{"DELETE", "/match/1", ""},
		{"PUT", "/cc", `{"enabled":false}`},
		{"PUT", "/settings", `{}`},
		{"POST", "/apply", ""},
	}
	for _, role := range []string{"readonly", "operator"} {
		for _, w := range writes {
			audited := 0
			_, r := newTestModule(t, role, &audited)
			rec := do(r, w.method, w.path, w.body)
			if rec.Code != http.StatusForbidden {
				t.Errorf("role=%s %s %s: want 403, got %d", role, w.method, w.path, rec.Code)
			}
			if audited != 0 {
				t.Errorf("role=%s %s %s: forbidden must not audit", role, w.method, w.path)
			}
		}
	}
}

func TestReadEndpointsAllowReadonly(t *testing.T) {
	reads := []string{"/ip", "/match", "/cc", "/settings", "/config"}
	for _, path := range reads {
		audited := 0
		_, r := newTestModule(t, "readonly", &audited)
		rec := do(r, "GET", path, "")
		if rec.Code == http.StatusForbidden {
			t.Errorf("GET %s must not require admin, got 403", path)
		}
	}
}

func TestCreateIPRejectsInjection(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "POST", "/ip", `{"action":"deny","cidr":"1.2.3.4; rm -rf /"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("injection cidr must 400, got %d", rec.Code)
	}
	if audited != 0 {
		t.Error("rejected-before-store request must not audit")
	}
}

func TestCreateIPRejectsBadAction(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "POST", "/ip", `{"action":"drop","cidr":"1.2.3.4"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad action must 400, got %d", rec.Code)
	}
}

func TestCreateMatchRejectsInjection(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "POST", "/match", `{"target":"uri","pattern":"$request_uri","action":"block"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("injection pattern must 400, got %d", rec.Code)
	}
}

func TestPutCCRejectsBadThreshold(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "PUT", "/cc", `{"enabled":true,"rate_per_sec":0,"zone_size_mb":10}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad cc threshold must 400, got %d", rec.Code)
	}
}

func TestPutSettingsRejectsBadPath(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)
	rec := do(r, "PUT", "/settings", `{"config_dir":"relative","http_conf_name":"a.conf","server_conf_name":"b.conf","log_path":"/var/log/x"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("relative config_dir must 400, got %d", rec.Code)
	}
}

func TestIPCRUDLifecycle(t *testing.T) {
	audited := 0
	_, r := newTestModule(t, "admin", &audited)

	rec := do(r, "POST", "/ip", `{"action":"deny","cidr":"10.0.0.0/8","enabled":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d: %s", rec.Code, rec.Body)
	}
	if audited != 1 {
		t.Errorf("create must audit once, got %d", audited)
	}

	rec = do(r, "GET", "/ip", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "10.0.0.0/8") {
		t.Errorf("list should contain created rule, got %d: %s", rec.Code, rec.Body)
	}

	rec = do(r, "DELETE", "/ip/1", "")
	if rec.Code != http.StatusNoContent {
		t.Errorf("delete want 204, got %d", rec.Code)
	}

	rec = do(r, "DELETE", "/ip/999", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("delete missing want 404, got %d", rec.Code)
	}
}

func TestApplyWithMockNginx(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)
	ng := &mockNginx{}
	m.ng = ng // inject mock
	// Point config dir at a temp dir so apply can write.
	set := DefaultSettings()
	set.ConfigDir = t.TempDir()
	set.NginxConf = ""
	if err := m.ws.setSettings(set); err != nil {
		t.Fatal(err)
	}

	rec := do(r, "POST", "/apply", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("apply want 200, got %d: %s", rec.Code, rec.Body)
	}
	if ng.tested != 1 || ng.reloaded != 1 {
		t.Errorf("apply should test+reload once, got tested=%d reloaded=%d", ng.tested, ng.reloaded)
	}
	if audited != 1 {
		t.Errorf("apply must audit once, got %d", audited)
	}
}

func TestConfigPreview(t *testing.T) {
	_, r := newTestModule(t, "admin", new(int))
	do(r, "POST", "/ip", `{"action":"allow","cidr":"1.2.3.4","enabled":true}`)
	rec := do(r, "GET", "/config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("preview want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "allow 1.2.3.4;") {
		t.Errorf("preview should render rule, got: %s", rec.Body)
	}
}
