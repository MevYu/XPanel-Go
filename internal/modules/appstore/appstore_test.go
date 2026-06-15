package appstore

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

type auditRec struct {
	mu      sync.Mutex
	entries []string
}

func (a *auditRec) fn(_ *int64, action, detail, _ string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, action+":"+detail)
}

func (a *auditRec) has(action string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, e := range a.entries {
		if strings.HasPrefix(e, action+":") {
			return true
		}
	}
	return false
}

// testModule 用 in-memory store + mockCompose 构造模块,并挂在 chi 路由上。
func testModule(t *testing.T, role string) (*Module, *mockCompose, *auditRec, http.Handler) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	as, err := newAppStore(st)
	if err != nil {
		t.Fatalf("newAppStore: %v", err)
	}
	mc := newMockCompose()
	ar := &auditRec{}
	m := &Module{
		as:      as,
		compose: mc,
		deps: Deps{
			Principal: func(*http.Request) (int64, string) { return 1, role },
			Audit:     ar.fn,
		},
	}
	r := chi.NewRouter()
	m.Routes(r)
	return m, mc, ar, r
}

func doJSON(r http.Handler, method, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestCatalogPublicReadable(t *testing.T) {
	_, _, _, r := testModule(t, "viewer")
	rec := doJSON(r, "GET", "/apps", "", nil)
	if rec.Code != 200 {
		t.Fatalf("catalog status %d", rec.Code)
	}
	var apps []App
	if err := json.Unmarshal(rec.Body.Bytes(), &apps); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(apps) != 8 {
		t.Errorf("expected 8 built-in apps, got %d", len(apps))
	}
	// compose 模板不应外泄给前端。
	if strings.Contains(rec.Body.String(), "image:") {
		t.Error("compose template leaked in catalog response")
	}
}

func TestInstallRequiresAdmin(t *testing.T) {
	_, mc, _, r := testModule(t, "operator")
	rec := doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin install should 403, got %d", rec.Code)
	}
	if len(mc.upCalls) != 0 {
		t.Error("compose up must not run for non-admin")
	}
}

func TestInstallHappyPath(t *testing.T) {
	_, mc, ar, r := testModule(t, "admin")
	rec := doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("install should 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(mc.upCalls) != 1 || mc.upCalls[0] != "redis-1" {
		t.Errorf("expected up for redis-1, got %v", mc.upCalls)
	}
	// 渲染的 compose 已写入项目目录。
	if len(mc.written) != 1 {
		t.Errorf("expected one compose written, got %d", len(mc.written))
	}
	for _, content := range mc.written {
		if !strings.Contains(content, "'S3cret!_pass'") {
			t.Errorf("password not yq-quoted in written compose: %s", content)
		}
	}
	if !ar.has("appstore.install") {
		t.Error("install should be audited")
	}
}

func TestInstallRejectsBadAppID(t *testing.T) {
	_, mc, _, r := testModule(t, "admin")
	rec := doJSON(r, "POST", "/install", `{"app_id":"../etc","params":{}}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad app id should 400, got %d", rec.Code)
	}
	if len(mc.upCalls) != 0 {
		t.Error("compose must not run for invalid app id")
	}
}

func TestInstallRejectsUnknownApp(t *testing.T) {
	_, _, _, r := testModule(t, "admin")
	rec := doJSON(r, "POST", "/install", `{"app_id":"notreal","params":{}}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown app should 400, got %d", rec.Code)
	}
}

func TestInstallRejectsInjectionParam(t *testing.T) {
	_, mc, _, r := testModule(t, "admin")
	// 试图通过密码注入 YAML 结构。
	// 密码含换行(YAML 结构破坏字符):JSON 里用 \n 转义,解码出真实换行进入参数值。
	rec := doJSON(r, "POST", "/install",
		"{\"app_id\":\"redis\",\"name\":\"redis-1\",\"params\":{\"port\":\"6379\",\"password\":\"badpass\\nevil\"}}", nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection param should 400, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(mc.upCalls) != 0 {
		t.Error("compose must not run when param validation fails")
	}
}

func TestInstallRejectsBadInstanceName(t *testing.T) {
	_, _, _, r := testModule(t, "admin")
	rec := doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"../escape","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad instance name should 400, got %d", rec.Code)
	}
}

func TestInstallDuplicateNameConflict(t *testing.T) {
	_, _, _, r := testModule(t, "admin")
	body := `{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`
	if rec := doJSON(r, "POST", "/install", body, nil); rec.Code != http.StatusCreated {
		t.Fatalf("first install: %d", rec.Code)
	}
	if rec := doJSON(r, "POST", "/install", body, nil); rec.Code != http.StatusConflict {
		t.Fatalf("duplicate name should 409, got %d", rec.Code)
	}
}

func TestToggleStartStop(t *testing.T) {
	_, mc, ar, r := testModule(t, "admin")
	doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)

	rec := doJSON(r, "POST", "/instances/1/stop", "", nil)
	if rec.Code != 200 {
		t.Fatalf("stop should 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(mc.stopCalls) != 1 {
		t.Errorf("expected one stop, got %v", mc.stopCalls)
	}
	var inst Instance
	json.Unmarshal(rec.Body.Bytes(), &inst)
	if inst.Status != "stopped" {
		t.Errorf("status should be stopped, got %s", inst.Status)
	}

	rec = doJSON(r, "POST", "/instances/1/start", "", nil)
	if rec.Code != 200 || len(mc.startCalls) != 1 {
		t.Errorf("start failed: %d starts=%v", rec.Code, mc.startCalls)
	}
	if !ar.has("appstore.stop") || !ar.has("appstore.start") {
		t.Error("toggle should be audited")
	}
}

func TestToggleRequiresOperator(t *testing.T) {
	_, _, _, radmin := testModule(t, "admin")
	doJSON(radmin, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)

	_, mc, _, r := testModule(t, "viewer")
	rec := doJSON(r, "POST", "/instances/1/stop", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("viewer toggle should 403, got %d", rec.Code)
	}
	if len(mc.stopCalls) != 0 {
		t.Error("compose stop must not run for viewer")
	}
}

func TestUninstallRequiresConfirmHeader(t *testing.T) {
	_, mc, _, r := testModule(t, "admin")
	doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)

	rec := doJSON(r, "DELETE", "/instances/1", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("uninstall without confirm should 428, got %d", rec.Code)
	}
	if len(mc.downCalls) != 0 {
		t.Error("compose down must not run without confirm header")
	}
}

func TestUninstallRequiresAdmin(t *testing.T) {
	_, _, _, radmin := testModule(t, "admin")
	doJSON(radmin, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)

	_, mc, _, r := testModule(t, "operator")
	rec := doJSON(r, "DELETE", "/instances/1", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator uninstall should 403, got %d", rec.Code)
	}
	if len(mc.downCalls) != 0 {
		t.Error("compose down must not run for operator")
	}
}

func TestUninstallHappyPathKeepsData(t *testing.T) {
	_, mc, ar, r := testModule(t, "admin")
	doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)

	rec := doJSON(r, "DELETE", "/instances/1", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("uninstall should 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(mc.downCalls) != 1 || mc.downCalls[0].removeVolumes {
		t.Errorf("expected down without -v, got %v", mc.downCalls)
	}
	if !ar.has("appstore.uninstall") {
		t.Error("uninstall should be audited")
	}
	// 实例已删除。
	if rec := doJSON(r, "GET", "/instances/1", "", nil); rec.Code != http.StatusNotFound {
		t.Errorf("instance should be gone, got %d", rec.Code)
	}
}

func TestUninstallDeleteData(t *testing.T) {
	_, mc, _, r := testModule(t, "admin")
	doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)

	rec := doJSON(r, "DELETE", "/instances/1?delete_data=true", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("uninstall should 204, got %d", rec.Code)
	}
	if len(mc.downCalls) != 1 || !mc.downCalls[0].removeVolumes {
		t.Errorf("expected down with -v, got %v", mc.downCalls)
	}
}

func TestSettingsGetPutRBAC(t *testing.T) {
	_, _, _, radmin := testModule(t, "admin")
	rec := doJSON(radmin, "GET", "/settings", "", nil)
	if rec.Code != 200 {
		t.Fatalf("get settings should 200, got %d", rec.Code)
	}
	var set Settings
	json.Unmarshal(rec.Body.Bytes(), &set)
	if set != DefaultSettings() {
		t.Errorf("expected defaults, got %+v", set)
	}

	// admin 可改。
	rec = doJSON(radmin, "PUT", "/settings", `{"apps_root":"/www/dk_apps","project_dir":"/www/dk_apps/_p"}`, nil)
	if rec.Code != 200 {
		t.Fatalf("admin put settings should 200, got %d (%s)", rec.Code, rec.Body.String())
	}

	// non-admin 不可改。
	_, _, _, rop := testModule(t, "operator")
	rec = doJSON(rop, "PUT", "/settings", `{"apps_root":"/x","project_dir":"/y"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put settings should 403, got %d", rec.Code)
	}
}

func TestSettingsPutRejectsBadPath(t *testing.T) {
	_, _, _, r := testModule(t, "admin")
	rec := doJSON(r, "PUT", "/settings", `{"apps_root":"relative","project_dir":"/y"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad path should 400, got %d", rec.Code)
	}
}

func TestInstallUpFailureRollsBack(t *testing.T) {
	_, mc, _, r := testModule(t, "admin")
	mc.upErr = errUnavailable
	rec := doJSON(r, "POST", "/install",
		`{"app_id":"redis","name":"redis-1","params":{"port":"6379","password":"S3cret!_pass"}}`, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("up failure should 500, got %d", rec.Code)
	}
	// 回滚:项目目录被清理,实例未记录。
	if len(mc.removedDir) != 1 {
		t.Errorf("expected project dir cleanup on up failure, got %v", mc.removedDir)
	}
	if rec := doJSON(r, "GET", "/instances", "", nil); !strings.Contains(rec.Body.String(), "[]") {
		t.Errorf("no instance should be recorded on up failure: %s", rec.Body.String())
	}
}
