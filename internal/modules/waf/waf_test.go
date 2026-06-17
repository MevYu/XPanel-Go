package waf

import (
	"encoding/json"
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
	return doH(r, method, path, body, nil)
}

func doH(r chi.Router, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, path, nil)
	} else {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	for k, v := range headers {
		req.Header.Set(k, v)
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

func TestToggleEndpointsRequireAdmin(t *testing.T) {
	toggles := []string{"/ip/1/toggle", "/match/1/toggle"}
	for _, role := range []string{"readonly", "operator"} {
		for _, path := range toggles {
			audited := 0
			_, r := newTestModule(t, role, &audited)
			rec := do(r, "POST", path, `{"enabled":false}`)
			if rec.Code != http.StatusForbidden {
				t.Errorf("role=%s POST %s: want 403, got %d", role, path, rec.Code)
			}
			if audited != 0 {
				t.Errorf("role=%s POST %s: forbidden must not audit", role, path)
			}
		}
	}
}

func TestToggleIPChangesState(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)

	rec := do(r, "POST", "/ip", `{"action":"deny","cidr":"10.0.0.0/8","enabled":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d: %s", rec.Code, rec.Body)
	}

	rec = do(r, "POST", "/ip/1/toggle", `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle want 200, got %d: %s", rec.Code, rec.Body)
	}
	rules, err := m.ws.listIP()
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Enabled {
		t.Errorf("toggle off did not persist: %+v", rules)
	}

	rec = do(r, "POST", "/ip/1/toggle", `{"enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle on want 200, got %d", rec.Code)
	}
	rules, _ = m.ws.listIP()
	if !rules[0].Enabled {
		t.Errorf("toggle on did not persist: %+v", rules)
	}

	rec = do(r, "POST", "/ip/999/toggle", `{"enabled":false}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("toggle missing want 404, got %d", rec.Code)
	}
}

func TestToggleMatchChangesState(t *testing.T) {
	m, r := newTestModule(t, "admin", new(int))

	rec := do(r, "POST", "/match", `{"target":"uri","pattern":"/wp-admin","action":"block","enabled":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create want 201, got %d: %s", rec.Code, rec.Body)
	}

	rec = do(r, "POST", "/match/1/toggle", `{"enabled":false}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle want 200, got %d: %s", rec.Code, rec.Body)
	}
	rules, err := m.ws.listMatch()
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].Enabled {
		t.Errorf("toggle off did not persist: %+v", rules)
	}
}

// TestToggleAffectsGeneratedConfig 验证启停单规则会影响生成的配置(关→不出现,开→出现)。
func TestToggleAffectsGeneratedConfig(t *testing.T) {
	_, r := newTestModule(t, "admin", new(int))
	do(r, "POST", "/ip", `{"action":"deny","cidr":"9.9.9.9","enabled":true}`)

	rec := do(r, "GET", "/config", "")
	if !strings.Contains(rec.Body.String(), "deny 9.9.9.9;") {
		t.Fatalf("enabled rule must appear in config, got: %s", rec.Body)
	}

	do(r, "POST", "/ip/1/toggle", `{"enabled":false}`)
	rec = do(r, "GET", "/config", "")
	if strings.Contains(rec.Body.String(), "9.9.9.9") {
		t.Errorf("disabled rule must not appear in config, got: %s", rec.Body)
	}
}

// TestGlobalSwitchPersistsAndGates 验证全局总开关经 PUT 持久化,且关闭时整体不拦。
func TestGlobalSwitchPersistsAndGates(t *testing.T) {
	m, r := newTestModule(t, "admin", new(int))
	do(r, "POST", "/ip", `{"action":"deny","cidr":"9.9.9.9","enabled":true}`)

	set := DefaultSettings()
	set.WAFEnabled = false
	body, _ := json.Marshal(set)
	rec := doH(r, "PUT", "/settings", string(body), map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("disable WAF want 200, got %d: %s", rec.Code, rec.Body)
	}

	got, err := m.ws.getSettings()
	if err != nil {
		t.Fatal(err)
	}
	if got.WAFEnabled {
		t.Error("waf_enabled=false did not persist")
	}

	// 全局关闭时,即便有启用 IP 规则,生成的配置不得含拦截指令。
	rec = do(r, "GET", "/config", "")
	if strings.Contains(rec.Body.String(), "deny 9.9.9.9;") {
		t.Errorf("globally-disabled WAF must not enforce rules, got: %s", rec.Body)
	}
}

// TestDisableWAFRequiresConfirmDanger 验证关闭全局总开关是危险操作:缺确认头被拒。
func TestDisableWAFRequiresConfirmDanger(t *testing.T) {
	audited := 0
	m, r := newTestModule(t, "admin", &audited)

	set := DefaultSettings()
	set.WAFEnabled = false
	body, _ := json.Marshal(set)

	rec := do(r, "PUT", "/settings", string(body))
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("disable without confirm want 428, got %d", rec.Code)
	}
	if audited != 0 {
		t.Error("rejected danger op must not audit")
	}
	got, _ := m.ws.getSettings()
	if !got.WAFEnabled {
		t.Error("rejected disable must not persist (WAF should stay enabled)")
	}
}

// TestEnableWAFNoConfirmNeeded 验证开启/保持开启不属危险操作,无需确认头。
func TestEnableWAFNoConfirmNeeded(t *testing.T) {
	_, r := newTestModule(t, "admin", new(int))
	set := DefaultSettings() // WAFEnabled=true
	body, _ := json.Marshal(set)
	rec := do(r, "PUT", "/settings", string(body))
	if rec.Code != http.StatusOK {
		t.Errorf("enabling WAF must not require confirm, got %d: %s", rec.Code, rec.Body)
	}
}
