package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// mockRunner 记录调用并返回可控结果,隔离真实 docker CLI。
type mockRunner struct {
	calls [][]string
	out   string
	err   error
	avail error
}

func (m *mockRunner) Run(_ context.Context, args ...string) (string, error) {
	m.calls = append(m.calls, args)
	return m.out, m.err
}
func (m *mockRunner) Available() error { return m.avail }

func (m *mockRunner) last() []string {
	if len(m.calls) == 0 {
		return nil
	}
	return m.calls[len(m.calls)-1]
}

func newTestModule(t *testing.T, role string, run Runner) (*Module, *int) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	audited := new(int)
	m := New(st, run, Deps{
		Principal: func(*http.Request) (int64, string) { return 7, role },
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
	m, _ := newTestModule(t, "admin", &mockRunner{})
	meta := m.Meta()
	if meta.ID != "docker" || meta.AlwaysOn {
		t.Errorf("must be id=docker, not AlwaysOn, got %+v", meta)
	}
	if meta.Name != "容器" || meta.Category != "应用" {
		t.Errorf("Name=容器 Category=应用 expected, got %q/%q", meta.Name, meta.Category)
	}
}

func TestHealthCheck(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockRunner{avail: http.ErrNotSupported})
	if m.HealthCheck() == nil {
		t.Error("HealthCheck should fail when daemon unavailable")
	}
	m2, _ := newTestModule(t, "admin", &mockRunner{})
	if m2.HealthCheck() != nil {
		t.Error("HealthCheck should pass when daemon available")
	}
}

func TestContainerListParsesJSON(t *testing.T) {
	run := &mockRunner{out: "{\"ID\":\"abc\",\"Names\":\"web\"}\n{\"ID\":\"def\",\"Names\":\"db\"}"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/containers", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"web"`) || !strings.Contains(rec.Body.String(), `"db"`) {
		t.Errorf("expected parsed array, got %s", rec.Body.String())
	}
	args := run.last()
	if len(args) < 2 || args[0] != "ps" || args[1] != "-a" {
		t.Errorf("expected ps -a, got %v", args)
	}
}

func TestContainerListRequiresOperator(t *testing.T) {
	m, _ := newTestModule(t, "viewer", &mockRunner{out: "{}"})
	rec := do(m, "GET", "/containers", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Errorf("non-operator should be 403, got %d", rec.Code)
	}
}

func TestContainerActionAuditsAndValidates(t *testing.T) {
	run := &mockRunner{out: "web"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/web/restart", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("action should audit once, got %d", *audited)
	}
	args := run.last()
	if len(args) != 2 || args[0] != "restart" || args[1] != "web" {
		t.Errorf("expected restart web, got %v", args)
	}
}

func TestContainerActionRejectsBadRef(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/containers/bad%20name/start", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad ref should be 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for invalid ref")
	}
}

func TestContainerRemoveRequiresConfirmAndAdmin(t *testing.T) {
	run := &mockRunner{out: "web"}
	// operator + confirm → still admin-only → 403
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "DELETE", "/containers/web", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusForbidden {
		t.Errorf("operator remove should 403, got %d", rec.Code)
	}

	// admin without confirm → 428
	m2, _ := newTestModule(t, "admin", run)
	rec = do(m2, "DELETE", "/containers/web", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run without confirm/admin")
	}

	// admin + confirm → ok, force remove
	m3, audited := newTestModule(t, "admin", run)
	rec = do(m3, "DELETE", "/containers/web", "", map[string]string{"X-Confirm-Danger": "yes"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin+confirm should 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("remove should audit, got %d", *audited)
	}
	args := run.last()
	if len(args) != 3 || args[0] != "rm" || args[1] != "-f" || args[2] != "web" {
		t.Errorf("expected rm -f web, got %v", args)
	}
}

func TestImagePullValidatesAndRuns(t *testing.T) {
	run := &mockRunner{out: "pulled"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/images/pull", `{"image":"nginx:1.25"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("pull should audit, got %d", *audited)
	}
	args := run.last()
	if len(args) != 2 || args[0] != "pull" || args[1] != "nginx:1.25" {
		t.Errorf("expected pull nginx:1.25, got %v", args)
	}
}

func TestImagePullRejectsInjection(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/images/pull", `{"image":"nginx; rm -rf /"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("injection image should 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for injection attempt")
	}
}

func TestImageRemoveDanger(t *testing.T) {
	run := &mockRunner{out: "deleted"}
	m, _ := newTestModule(t, "admin", run)
	rec := do(m, "DELETE", "/images/nginx", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "DELETE", "/images/nginx", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin+confirm should 200, got %d", rec.Code)
	}
	if run.last()[0] != "rmi" {
		t.Errorf("expected rmi, got %v", run.last())
	}
}

func TestComposeUpUsesProjectDir(t *testing.T) {
	run := &mockRunner{out: "started"}
	m, audited := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/compose/web/up", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("up should audit, got %d", *audited)
	}
	args := run.last()
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "compose --project-directory "+defaultComposeDir+"/web -p web up -d") {
		t.Errorf("unexpected compose args: %v", args)
	}
}

func TestComposeDownDanger(t *testing.T) {
	run := &mockRunner{out: "down"}
	m, _ := newTestModule(t, "admin", run)
	rec := do(m, "POST", "/compose/web/down", "", nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Errorf("missing confirm should 428, got %d", rec.Code)
	}
	rec = do(m, "POST", "/compose/web/down", "", map[string]string{"X-Confirm-Danger": "y"})
	if rec.Code != http.StatusOK {
		t.Fatalf("admin+confirm should 200, got %d", rec.Code)
	}
}

func TestComposeRejectsBadProject(t *testing.T) {
	run := &mockRunner{}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "POST", "/compose/Bad-NAME/up", "", nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("invalid project should 400, got %d", rec.Code)
	}
	if len(run.calls) != 0 {
		t.Error("docker must not run for invalid project")
	}
}

func TestNetworkAndVolumeList(t *testing.T) {
	run := &mockRunner{out: `{"Name":"bridge"}`}
	m, _ := newTestModule(t, "operator", run)
	for _, path := range []string{"/networks", "/volumes"} {
		rec := do(m, "GET", path, "", nil)
		if rec.Code != http.StatusOK {
			t.Errorf("%s status %d", path, rec.Code)
		}
	}
}

func TestSettingsRoundTripAdminOnly(t *testing.T) {
	run := &mockRunner{}
	// non-admin GET → 403
	m, _ := newTestModule(t, "operator", run)
	if rec := do(m, "GET", "/settings", "", nil); rec.Code != http.StatusForbidden {
		t.Errorf("operator settings GET should 403, got %d", rec.Code)
	}

	m2, audited := newTestModule(t, "admin", run)
	// default GET
	rec := do(m2, "GET", "/settings", "", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), defaultComposeDir) {
		t.Fatalf("default settings GET failed: %d %s", rec.Code, rec.Body.String())
	}
	// PUT new dirs
	rec = do(m2, "PUT", "/settings", `{"compose_dir":"/srv/compose","docker_root":"/data/docker"}`, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("settings PUT failed: %d %s", rec.Code, rec.Body.String())
	}
	if *audited != 1 {
		t.Errorf("settings PUT should audit, got %d", *audited)
	}
	rec = do(m2, "GET", "/settings", "", nil)
	if !strings.Contains(rec.Body.String(), "/srv/compose") {
		t.Errorf("settings not persisted: %s", rec.Body.String())
	}
}

func TestSettingsRejectsRelativePath(t *testing.T) {
	m, _ := newTestModule(t, "admin", &mockRunner{})
	rec := do(m, "PUT", "/settings", `{"compose_dir":"relative","docker_root":"/data"}`, nil)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("relative compose_dir should 400, got %d", rec.Code)
	}
}

func TestContainerLogsTailClamped(t *testing.T) {
	run := &mockRunner{out: "log output"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/containers/web/logs?tail=50", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	args := run.last()
	joined := strings.Join(args, " ")
	if joined != "logs --tail 50 web" {
		t.Errorf("expected 'logs --tail 50 web', got %v", args)
	}
}

func TestDockerErrorMaskedAsBadGateway(t *testing.T) {
	run := &mockRunner{err: context.DeadlineExceeded, out: "/secret/internal/path leaked"}
	m, _ := newTestModule(t, "operator", run)
	rec := do(m, "GET", "/containers", "", nil)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("docker failure should 502, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "/secret/internal/path") {
		t.Errorf("internal output leaked to client: %s", rec.Body.String())
	}
}
