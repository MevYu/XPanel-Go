package python

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *pyStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ps, err := newPyStore(st)
	if err != nil {
		t.Fatalf("init py store: %v", err)
	}
	return ps
}

func TestProjectCRUD(t *testing.T) {
	ss := newTestStore(t)
	uid := int64(7)
	id, err := ss.create(Project{
		Name: "api", ProjectDir: "/www/python/api", VenvDir: "/www/python/venv/api",
		Interpreter: "python3.11", StartKind: StartGunicorn, AppTarget: "wsgi:app",
		Port: 8000, Workers: 3, CreatedBy: &uid,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	p, err := ss.get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if p.Name != "api" || p.Port != 8000 || p.Workers != 3 || p.StartKind != StartGunicorn ||
		p.CreatedBy == nil || *p.CreatedBy != 7 {
		t.Fatalf("round-trip mismatch: %+v", p)
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
	base := Project{Name: "dup", ProjectDir: "/a", VenvDir: "/v", Interpreter: "python3", StartKind: StartScript, AppTarget: "run.py"}
	if _, err := ss.create(base); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := ss.create(base); err == nil {
		t.Fatal("duplicate name must violate UNIQUE constraint")
	}
}

func TestSettingsDefaultAndOverride(t *testing.T) {
	ss := newTestStore(t)
	set, err := ss.loadSettings()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.ProjectRoot != defaultProjectRoot || set.VenvRoot != defaultVenvRoot ||
		set.Interpreter != defaultInterpreter || set.ConfDir != defaultConfDir || set.LogDir != defaultLogDir {
		t.Fatalf("expected defaults, got %+v", set)
	}
	override := Settings{
		ProjectRoot: "/srv/py", VenvRoot: "/srv/venv", Interpreter: "python3.12",
		ConfDir: "/custom/conf", LogDir: "/custom/log",
	}
	if err := ss.saveSettings(override); err != nil {
		t.Fatalf("save: %v", err)
	}
	set, _ = ss.loadSettings()
	if set != override {
		t.Fatalf("override not persisted, got %+v", set)
	}
}
