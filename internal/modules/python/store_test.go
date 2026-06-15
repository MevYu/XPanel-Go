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

// TestLoadSettingsRevalidatesPersistedValues 锁定 Low 修复:旁路 PUT 校验直接写入 DB 的
// 非法值(相对路径、坏解释器)在载入时被重新校验并回退默认,不进入命令/路径拼接。
func TestLoadSettingsRevalidatesPersistedValues(t *testing.T) {
	ss := newTestStore(t)
	// 直接写库,绕过 saveSettings/PUT 的校验,模拟脏数据。
	dirty := map[string]string{
		settingProjectRoot: "relative/dir",    // 非绝对
		settingVenvRoot:    "/bad\nnewline",   // 含控制字符
		settingInterpreter: "python2; rm -rf", // 坏解释器
		settingConfDir:     "/etc/ok",         // 合法,应保留
		settingLogDir:      "../escape",       // 非绝对
	}
	const q = `INSERT INTO python_settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`
	for k, v := range dirty {
		if _, err := ss.db.Exec(q, k, v); err != nil {
			t.Fatalf("seed dirty %s: %v", k, err)
		}
	}
	set, err := ss.loadSettings()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if set.ProjectRoot != defaultProjectRoot {
		t.Errorf("invalid project_root must fall back to default, got %q", set.ProjectRoot)
	}
	if set.VenvRoot != defaultVenvRoot {
		t.Errorf("invalid venv_root must fall back to default, got %q", set.VenvRoot)
	}
	if set.Interpreter != defaultInterpreter {
		t.Errorf("invalid interpreter must fall back to default, got %q", set.Interpreter)
	}
	if set.LogDir != defaultLogDir {
		t.Errorf("invalid log_dir must fall back to default, got %q", set.LogDir)
	}
	if set.ConfDir != "/etc/ok" {
		t.Errorf("valid conf_dir must be kept, got %q", set.ConfDir)
	}
}
