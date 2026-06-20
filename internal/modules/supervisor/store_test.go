package supervisor

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *supStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ss, err := newSupStore(st)
	if err != nil {
		t.Fatalf("init sup store: %v", err)
	}
	return ss
}

func TestProgramCRUD(t *testing.T) {
	ss := newTestStore(t)
	uid := int64(7)
	id, err := ss.create(Program{
		Name: "app", Command: "/bin/run", Directory: "/opt",
		AutoRestart: true, Numprocs: 2, User: "www", Priority: 500, CreatedBy: &uid,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	p, err := ss.get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if p.Name != "app" || !p.AutoRestart || p.Numprocs != 2 || p.CreatedBy == nil || *p.CreatedBy != 7 {
		t.Fatalf("round-trip mismatch: %+v", p)
	}
	if p.User != "www" || p.Priority != 500 {
		t.Fatalf("user/priority round-trip mismatch: %+v", p)
	}
	list, err := ss.list()
	if err != nil || len(list) != 1 {
		t.Fatalf("list: %v len=%d", err, len(list))
	}
	if err := ss.delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if list, _ := ss.list(); len(list) != 0 {
		t.Fatalf("expected empty after delete, got %d", len(list))
	}
}

func TestCreateRejectsDuplicateName(t *testing.T) {
	ss := newTestStore(t)
	if _, err := ss.create(Program{Name: "dup", Command: "x", Directory: "/o", Numprocs: 1}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := ss.create(Program{Name: "dup", Command: "y", Directory: "/o", Numprocs: 1}); err == nil {
		t.Fatal("duplicate name must violate UNIQUE constraint")
	}
}

func TestSettingsDefaultAndOverride(t *testing.T) {
	ss := newTestStore(t)
	set, err := ss.loadSettings()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.ConfDir != defaultConfDir || set.LogDir != defaultLogDir {
		t.Fatalf("expected defaults, got %+v", set)
	}
	if err := ss.saveSettings(Settings{ConfDir: "/custom/conf", LogDir: "/custom/log"}); err != nil {
		t.Fatalf("save: %v", err)
	}
	set, _ = ss.loadSettings()
	if set.ConfDir != "/custom/conf" || set.LogDir != "/custom/log" {
		t.Fatalf("override not persisted, got %+v", set)
	}
}
