package service

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

var errBoom = errors.New("boom")

type fakeRunner struct {
	units, files       string
	unitsErr, filesErr error
	versions           map[string]string // name -> version,缺失返回空
}

func (f *fakeRunner) listUnits() (string, error)     { return f.units, f.unitsErr }
func (f *fakeRunner) listUnitFiles() (string, error) { return f.files, f.filesErr }
func (f *fakeRunner) serviceVersion(name string) string {
	return f.versions[name]
}

func newWithRunner(deps Deps, r commandRunner) *Module {
	m := New(deps)
	m.runner = r
	return m
}

func TestServicesEndpointReturnsJSON(t *testing.T) {
	m := newWithRunner(fakeDeps("readonly", new(int)),
		&fakeRunner{units: sampleListUnits, files: sampleListUnitFiles})
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/services", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("readonly GET /services should be 200, got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json; charset=utf-8" {
		t.Errorf("unexpected content-type %q", ct)
	}
	var got []Service
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("body not a JSON array: %v\nbody=%s", err, rec.Body.String())
	}
	if len(got) != 5 {
		t.Fatalf("want 5 services, got %d", len(got))
	}
	var nginx *Service
	for i := range got {
		if got[i].Name == "nginx.service" {
			nginx = &got[i]
		}
	}
	if nginx == nil {
		t.Fatal("nginx.service missing from response")
	}
	if nginx.Active != "active" || nginx.Sub != "running" || nginx.Enabled != "enabled" {
		t.Errorf("nginx fields wrong: %+v", *nginx)
	}
}

func TestServicesEndpointFailureMasksError(t *testing.T) {
	m := newWithRunner(fakeDeps("admin", new(int)),
		&fakeRunner{unitsErr: errBoom})
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/services", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("runner failure should be 500, got %d", rec.Code)
	}
	if body := rec.Body.String(); body == errBoom.Error()+"\n" {
		t.Errorf("response leaked underlying error: %q", body)
	}
}
