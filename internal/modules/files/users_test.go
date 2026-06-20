package files

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestListUsersAdminReturnsRoot(t *testing.T) {
	m, _, _ := newModule(t, "admin")
	r := panelRouter(m)
	rec := req(t, r, "GET", "/users", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("users want 200, got %d", rec.Code)
	}
	var out []struct {
		Name  string `json:"name"`
		Group string `json:"group"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("want non-empty user list")
	}
	found := false
	for _, u := range out {
		if u.Name == "root" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("want root in user list, got %+v", out)
	}
}

func TestListUsersNonAdminForbidden(t *testing.T) {
	m, _, _ := newModule(t, "operator")
	r := panelRouter(m)
	rec := req(t, r, "GET", "/users", "", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin users want 403, got %d", rec.Code)
	}
}
