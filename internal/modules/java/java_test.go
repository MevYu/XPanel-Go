package java

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockPM 记录调用并返回可控结果,隔离真实 supervisorctl/Tomcat/文件系统。
type mockPM struct {
	applies   []string // 写过 supervisor 配置的 name
	removes   []string
	deploys   []string // 部署到 Tomcat 的 name
	undeploys []string
	actions   []string // "verb name"
	lastSpec  ProcessSpec
	lastWar   string
	avail     error
	applyErr  error
	deployErr error
	versions  []string
}

func (m *mockPM) Apply(_ string, spec ProcessSpec) error {
	m.applies = append(m.applies, spec.Name)
	m.lastSpec = spec
	return m.applyErr
}
func (m *mockPM) Remove(_, name string) error { m.removes = append(m.removes, name); return nil }
func (m *mockPM) Deploy(_, name, war string) error {
	m.deploys = append(m.deploys, name)
	m.lastWar = war
	return m.deployErr
}
func (m *mockPM) Undeploy(_, name string) error {
	m.undeploys = append(m.undeploys, name)
	return nil
}
func (m *mockPM) Action(verb, name string) (string, error) {
	m.actions = append(m.actions, verb+" "+name)
	return "ok", nil
}
func (m *mockPM) Status(name string) (string, error)                 { return "RUNNING " + name, nil }
func (m *mockPM) TailLog(name string, _ int, _ bool) (string, error) { return "log " + name, nil }
func (m *mockPM) JavaVersions() []string                             { return m.versions }
func (m *mockPM) Available() error                                   { return m.avail }

func newTestModule(t *testing.T, role string, pm ProcessManager) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, pm, Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(*int64, string, string, string) { *audited++ },
	})
	return m, audited
}

func do(m *Module, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	r := chi.NewRouter()
	m.Routes(r)
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

func TestMetaSwitchable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	meta := m.Meta()
	if meta.ID != "java" || meta.AlwaysOn {
		t.Errorf("must be id=java, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "网站" || meta.Name != "Java 项目" {
		t.Errorf("unexpected meta %+v", meta)
	}
}

func TestNavPath(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	nav := m.Nav()
	if len(nav) != 1 || nav[0].Path != "/java" {
		t.Errorf("unexpected nav %+v", nav)
	}
}

func TestHealthCheckUnavailable(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{avail: http.ErrNotSupported})
	if m.HealthCheck() == nil {
		t.Error("HealthCheck should fail when backend unavailable")
	}
}

func TestCreateJarHappyPath(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "operator", pm)
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","java_version":"17","jvm_args":"-Xmx512m","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(pm.applies) != 1 || pm.applies[0] != "web" {
		t.Fatalf("expected apply for web, got %v", pm.applies)
	}
	if pm.lastSpec.ArtifactPath != "/www/java/web/app.jar" {
		t.Fatalf("artifact should resolve under base, got %q", pm.lastSpec.ArtifactPath)
	}
	if pm.lastSpec.Port != 8080 || pm.lastSpec.JavaPath != "/usr/lib/jvm/default/bin" {
		t.Fatalf("spec wrong: %+v", pm.lastSpec)
	}
	if pm.lastSpec.JVMArgs != "-Xmx512m" {
		t.Fatalf("jvm args not passed: %+v", pm.lastSpec)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestCreateTomcatDeploysWar(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "operator", pm)
	body := `{"name":"shop","type":"tomcat","artifact_path":"shop/shop.war","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(pm.deploys) != 1 || pm.deploys[0] != "shop" {
		t.Fatalf("expected deploy for shop, got %v", pm.deploys)
	}
	if len(pm.applies) != 0 {
		t.Fatalf("tomcat must not write supervisor config, got %v", pm.applies)
	}
	if pm.lastWar != "/www/java/shop/shop.war" {
		t.Fatalf("war path wrong: %q", pm.lastWar)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestCreateTomcatRejectsJarArtifact(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"shop","type":"tomcat","artifact_path":"shop/shop.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("tomcat must require .war, got %d", rec.Code)
	}
	if len(pm.deploys) != 0 {
		t.Fatal("must not deploy on wrong suffix")
	}
}

func TestCreateRejectsBadType(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","type":"exe","artifact_path":"web/app.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad type should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsInjectionName(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web;rm -rf /","type":"jar","artifact_path":"web/app.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection name should 400, got %d", rec.Code)
	}
	if len(pm.applies) != 0 {
		t.Fatalf("must not apply on invalid input, got %v", pm.applies)
	}
}

func TestCreateRejectsInjectionJVMArgs(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := "{\"name\":\"web\",\"type\":\"jar\",\"artifact_path\":\"web/app.jar\",\"jvm_args\":\"-Xmx1g; rm -rf /\",\"port\":8080}"
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("injection jvm args should 400, got %d", rec.Code)
	}
	if len(pm.applies) != 0 {
		t.Fatal("must not apply on injection")
	}
}

func TestCreateRejectsPathTraversal(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","type":"jar","artifact_path":"../../etc/app.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("path traversal should 400, got %d", rec.Code)
	}
	if len(pm.applies) != 0 {
		t.Fatal("must not apply on path escape")
	}
}

func TestCreateRejectsBadPort(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","port":0}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("port 0 should 400, got %d", rec.Code)
	}
}

func TestCreateRejectsBadJavaVersion(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","java_version":"latest; rm","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("bad java version should 400, got %d", rec.Code)
	}
}

func TestCreateRequiresWriter(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "readonly", pm)
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly create should 403, got %d", rec.Code)
	}
	if *audited != 0 || len(pm.applies) != 0 {
		t.Fatal("forbidden create must not audit or apply")
	}
}

func TestStopRequiresConfirm(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	id := seedProject(t, m)
	rec := do(m, "POST", "/projects/"+id+"/stop", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("stop without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "POST", "/projects/"+id+"/stop", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("stop with confirm should 200, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestRestartNoConfirmNeeded(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	id := seedProject(t, m)
	rec := do(m, "POST", "/projects/"+id+"/restart", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("restart should 200, got %d", rec.Code)
	}
}

func TestDeleteRequiresAdminAndConfirm(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "operator", pm)
	id := seedProject(t, m)

	rec := do(m, "DELETE", "/projects/"+id, "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "DELETE", "/projects/"+id, "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator delete should 403, got %d", rec.Code)
	}
}

func TestDeleteAdminConfirmedRemovesConfig(t *testing.T) {
	pm := &mockPM{}
	m, audited := newTestModule(t, "admin", pm)
	id := seedProject(t, m)
	*audited = 0
	rec := do(m, "DELETE", "/projects/"+id, "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin confirmed delete should 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if len(pm.removes) != 1 {
		t.Fatalf("expected config removal, got %v", pm.removes)
	}
	// 删除前应先 stop。
	if len(pm.actions) != 1 || !strings.HasPrefix(pm.actions[0], "stop ") {
		t.Fatalf("expected stop before delete, got %v", pm.actions)
	}
	if *audited != 1 {
		t.Fatalf("expected 1 audit, got %d", *audited)
	}
}

func TestDeleteTomcatUndeploys(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "admin", pm)
	body := `{"name":"shop","type":"tomcat","artifact_path":"shop/shop.war","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed tomcat failed: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(m, "DELETE", "/projects/1", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete should 204, got %d", rec.Code)
	}
	if len(pm.undeploys) != 1 || pm.undeploys[0] != "shop" {
		t.Fatalf("expected undeploy, got %v", pm.undeploys)
	}
	if len(pm.removes) != 0 {
		t.Fatal("tomcat delete must not touch supervisor config")
	}
}

func TestPutSettingsRequiresAdmin(t *testing.T) {
	m, _ := newTestModule(t, "operator", &mockPM{})
	rec := do(m, "PUT", "/settings", `{"base_dir":"/a","jdk_dir":"/b","tomcat_dir":"/t","conf_dir":"/c","log_dir":"/d"}`, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator put settings should 403, got %d", rec.Code)
	}
}

func TestPutSettingsValidatesPaths(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	rec := do(m, "PUT", "/settings", `{"base_dir":"relative","jdk_dir":"/b","tomcat_dir":"/t","conf_dir":"/c","log_dir":"/d"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-absolute base_dir should 400, got %d", rec.Code)
	}
}

func TestSettingsRoundTripViaAPI(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockPM{})
	rec := do(m, "PUT", "/settings",
		`{"base_dir":"/srv/java","jdk_dir":"/opt/jdk17/bin","tomcat_dir":"/opt/tomcat","conf_dir":"/etc/sv","log_dir":"/var/log/java"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("admin put settings should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	rec = do(m, "GET", "/settings", "", nil)
	if !strings.Contains(rec.Body.String(), "/srv/java") || !strings.Contains(rec.Body.String(), "/opt/tomcat") {
		t.Fatalf("settings not persisted: %s", rec.Body.String())
	}
}

func TestSettingsAffectProjectSpec(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "admin", pm)
	rec := do(m, "PUT", "/settings",
		`{"base_dir":"/srv/java","jdk_dir":"/opt/jdk17/bin","tomcat_dir":"/opt/tomcat","conf_dir":"/etc/sv","log_dir":"/var/log/java"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings failed: %d", rec.Code)
	}
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","port":8080}`
	rec = do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}
	if pm.lastSpec.ArtifactPath != "/srv/java/web/app.jar" || pm.lastSpec.JavaPath != "/opt/jdk17/bin" {
		t.Fatalf("settings not applied to spec: %+v", pm.lastSpec)
	}
}

func TestSettingsAffectTomcatDeploy(t *testing.T) {
	pm := &mockPM{}
	m, _ := newTestModule(t, "admin", pm)
	rec := do(m, "PUT", "/settings",
		`{"base_dir":"/srv/java","jdk_dir":"/opt/jdk17/bin","tomcat_dir":"/opt/tomcat","conf_dir":"/etc/sv","log_dir":"/var/log/java"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("put settings failed: %d", rec.Code)
	}
	body := `{"name":"shop","type":"tomcat","artifact_path":"shop/shop.war","port":8080}`
	rec = do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create failed: %d %s", rec.Code, rec.Body.String())
	}
	if pm.lastWar != "/srv/java/shop/shop.war" {
		t.Fatalf("war path wrong: %q", pm.lastWar)
	}
}

func TestVersionsEndpoint(t *testing.T) {
	pm := &mockPM{versions: []string{"17.0.9", "21.0.1"}}
	m, _ := newTestModule(t, "readonly", pm)
	rec := do(m, "GET", "/versions", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "17.0.9") {
		t.Fatalf("versions endpoint wrong: %d %s", rec.Code, rec.Body.String())
	}
}

func TestVersionsEmptyReturnsArray(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockPM{})
	rec := do(m, "GET", "/versions", "", nil)
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty versions should be [], got %q", rec.Body.String())
	}
}

func TestListEmptyReturnsArray(t *testing.T) {
	m, _ := newTestModule(t, "readonly", &mockPM{})
	rec := do(m, "GET", "/projects", "", nil)
	if rec.Code != http.StatusOK || strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("empty list should be [], got %d %q", rec.Code, rec.Body.String())
	}
}

func TestCreateRollbackOnProvisionFailure(t *testing.T) {
	pm := &mockPM{applyErr: http.ErrNotSupported}
	m, _ := newTestModule(t, "operator", pm)
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("provision failure should 500, got %d", rec.Code)
	}
	// 元数据应回滚:列表为空。
	rec = do(m, "GET", "/projects", "", nil)
	if strings.TrimSpace(rec.Body.String()) != "[]" {
		t.Fatalf("metadata must be rolled back, got %q", rec.Body.String())
	}
}

// seedProject 经由真实 create handler 落一条 jar 项目,返回其 id 字符串。
func seedProject(t *testing.T, m *Module) string {
	t.Helper()
	body := `{"name":"web","type":"jar","artifact_path":"web/app.jar","port":8080}`
	rec := do(m, "POST", "/projects", body, nil)
	if rec.Code != http.StatusCreated {
		t.Fatalf("seed failed: %d %s", rec.Code, rec.Body.String())
	}
	return "1"
}
