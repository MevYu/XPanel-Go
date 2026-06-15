package appstore

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *appStore {
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
	return as
}

func TestAppStoreCRUD(t *testing.T) {
	as := newTestStore(t)
	uid := int64(7)
	id, err := as.create(Instance{
		AppID: "redis", Name: "redis-1", Params: map[string]string{"port": "6379"},
		Compose: "services: {}", ProjectDir: "/opt/xpanel/apps/_projects/redis-1", CreatedBy: &uid,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := as.get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "redis-1" || got.Status != "running" || got.Params["port"] != "6379" {
		t.Errorf("unexpected instance: %+v", got)
	}
	if got.CreatedBy == nil || *got.CreatedBy != 7 {
		t.Errorf("created_by not persisted: %+v", got.CreatedBy)
	}

	if err := as.setStatus(id, "stopped"); err != nil {
		t.Fatalf("setStatus: %v", err)
	}
	got, _ = as.get(id)
	if got.Status != "stopped" {
		t.Errorf("status not updated: %s", got.Status)
	}

	list, err := as.list()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}

	if err := as.delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := as.get(id); err == nil {
		t.Error("instance should be gone after delete")
	}
}

func TestAppStoreNameUnique(t *testing.T) {
	as := newTestStore(t)
	if _, err := as.create(Instance{AppID: "redis", Name: "dup", Params: map[string]string{}, Compose: "x", ProjectDir: "/p"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := as.create(Instance{AppID: "redis", Name: "dup", Params: map[string]string{}, Compose: "x", ProjectDir: "/p2"}); err == nil {
		t.Error("duplicate name should fail unique constraint")
	}
}

func TestAppStoreSettingsRoundTrip(t *testing.T) {
	as := newTestStore(t)
	got, err := as.getSettings()
	if err != nil {
		t.Fatalf("getSettings: %v", err)
	}
	if got != DefaultSettings() {
		t.Errorf("expected defaults, got %+v", got)
	}
	want := Settings{AppsRoot: "/www/dk_apps", ProjectDir: "/www/dk_apps/_p"}
	if err := as.putSettings(want); err != nil {
		t.Fatalf("putSettings: %v", err)
	}
	got, _ = as.getSettings()
	if got != want {
		t.Errorf("settings round-trip: got %+v want %+v", got, want)
	}
}
