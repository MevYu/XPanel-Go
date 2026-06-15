package terminal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func fakeDeps(role string, audited *int) Deps {
	return Deps{
		Principal: func(*http.Request) (int64, string) { return 1, role },
		Audit:     func(userID *int64, action, detail, ip string) { *audited++ },
	}
}

func TestMetaSwitchable(t *testing.T) {
	m := New(fakeDeps("admin", new(int)))
	meta := m.Meta()
	if meta.ID != "terminal" || meta.AlwaysOn {
		t.Errorf("terminal must be id=terminal, not AlwaysOn, got %+v", meta)
	}
	if meta.Category != "系统" {
		t.Errorf("terminal category must be 系统, got %q", meta.Category)
	}
}

func TestTicketRequiresOperator(t *testing.T) {
	audited := 0
	m := New(fakeDeps("readonly", &audited))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/ticket", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("readonly ticket must be 403, got %d", rec.Code)
	}
}

func TestTicketIssuedToOperator(t *testing.T) {
	m := New(fakeDeps("operator", new(int)))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/ticket", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("operator ticket must be 200, got %d", rec.Code)
	}
	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("ticket response must be JSON: %v", err)
	}
	if body["ticket"] == "" {
		t.Fatal("ticket response must carry a non-empty ticket")
	}
}

func TestWSRejectsBadTicket(t *testing.T) {
	m := New(fakeDeps("operator", new(int)))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ws?ticket=bogus", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("WS with bad ticket must be 401, got %d", rec.Code)
	}
}

func TestWSRejectsMissingTicket(t *testing.T) {
	m := New(fakeDeps("operator", new(int)))
	r := chi.NewRouter()
	m.Routes(r)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ws", nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("WS without ticket must be 401, got %d", rec.Code)
	}
}

// 票据一次性:消费后再连必须 401。这里复用 store 直接签发,避免触发真实 WS 升级。
func TestWSTicketSingleUseAtRoute(t *testing.T) {
	m := New(fakeDeps("operator", new(int)))
	r := chi.NewRouter()
	m.Routes(r)

	tok := m.tickets.issue(1, "operator")
	if _, ok := m.tickets.consume(tok); !ok {
		t.Fatal("first consume should succeed")
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ws?ticket="+tok, nil)
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("already-consumed ticket must be 401 at /ws, got %d", rec.Code)
	}
}
