package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestMetaAlwaysOn(t *testing.T) {
	m := New()
	if m.Meta().ID != "dashboard" || !m.Meta().AlwaysOn {
		t.Errorf("dashboard must be id=dashboard AlwaysOn, got %+v", m.Meta())
	}
}

func TestMetricsEndpoint(t *testing.T) {
	r := chi.NewRouter()
	New().Routes(r)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status %d", rec.Code)
	}
	if !contains(rec.Body.String(), "mem_total") {
		t.Errorf("metrics body missing mem_total: %s", rec.Body.String())
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
