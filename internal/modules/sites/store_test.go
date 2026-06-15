package sites

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *siteStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ss, err := newSiteStore(st)
	if err != nil {
		t.Fatalf("newSiteStore: %v", err)
	}
	return ss
}

func TestSettingsRoundTripDefaults(t *testing.T) {
	ss := newTestStore(t)
	// 无行 → 默认
	got, err := ss.getSettings()
	if err != nil {
		t.Fatalf("getSettings: %v", err)
	}
	if got != DefaultSettings() {
		t.Errorf("uninitialized settings = %+v, want defaults", got)
	}
	// 写入后读回
	want := Settings{WebRoot: "/srv/web", ConfDir: "/etc/nginx/sites", LogDir: "/var/log/nginx", PHPSocket: "/run/php/x.sock"}
	if err := ss.putSettings(want); err != nil {
		t.Fatalf("putSettings: %v", err)
	}
	got, _ = ss.getSettings()
	if got != want {
		t.Errorf("settings round trip = %+v, want %+v", got, want)
	}
	// 再次 put 覆盖(单行 upsert)
	want.WebRoot = "/srv/web2"
	if err := ss.putSettings(want); err != nil {
		t.Fatalf("putSettings update: %v", err)
	}
	got, _ = ss.getSettings()
	if got.WebRoot != "/srv/web2" {
		t.Errorf("settings update not applied: %+v", got)
	}
}

func TestSiteCRUD(t *testing.T) {
	ss := newTestStore(t)
	uid := int64(7)
	id, err := ss.create(Site{
		Name: "example.com", Domains: []string{"example.com", "www.example.com"},
		Kind: "static", Listen: 80, Enabled: true, Config: "server {}", CreatedBy: &uid,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := ss.get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "example.com" || len(got.Domains) != 2 || !got.Enabled {
		t.Errorf("unexpected site: %+v", got)
	}
	// unique name
	if _, err := ss.create(Site{Name: "example.com", Domains: []string{"x.com"}, Kind: "static", Listen: 80}); err == nil {
		t.Error("duplicate name should violate unique constraint")
	}
	// getByName
	if _, err := ss.getByName("example.com"); err != nil {
		t.Errorf("getByName: %v", err)
	}
	// toggle
	if err := ss.setEnabled(id, false); err != nil {
		t.Fatalf("setEnabled: %v", err)
	}
	got, _ = ss.get(id)
	if got.Enabled {
		t.Error("site should be disabled")
	}
	// delete
	if err := ss.delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ss.get(id); err == nil {
		t.Error("deleted site should not be found")
	}
}
