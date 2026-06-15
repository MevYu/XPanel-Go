package waf

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// mockNginx 记录调用并按字段控制 Test/Reload 成败,供测试 apply 流程。
type mockNginx struct {
	testErr   error
	reloadErr error
	tested    int
	reloaded  int
}

func (m *mockNginx) Available() error { return nil }
func (m *mockNginx) Test(string) (string, error) {
	m.tested++
	return "test-output", m.testErr
}
func (m *mockNginx) Reload() (string, error) {
	m.reloaded++
	return "reload-output", m.reloadErr
}

func testSettings(t *testing.T) Settings {
	dir := t.TempDir()
	s := DefaultSettings()
	s.ConfigDir = dir
	s.NginxConf = "" // mock ignores path
	return s
}

func TestApplyWritesAndReloadsOnTestPass(t *testing.T) {
	set := testSettings(t)
	ng := &mockNginx{}
	rs := RuleSet{IPRules: []IPRule{{Action: "deny", CIDR: "1.2.3.4", Enabled: true}}, CC: DefaultCCConfig()}

	if _, err := (applier{ng: ng}).apply(set, rs); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if ng.tested != 1 || ng.reloaded != 1 {
		t.Errorf("expected 1 test + 1 reload, got tested=%d reloaded=%d", ng.tested, ng.reloaded)
	}
	b, err := os.ReadFile(set.serverConfPath())
	if err != nil {
		t.Fatalf("server conf not written: %v", err)
	}
	if !strings.Contains(string(b), "deny 1.2.3.4;") {
		t.Errorf("server conf missing rule:\n%s", b)
	}
}

func TestApplyRollsBackOnTestFail(t *testing.T) {
	set := testSettings(t)
	// Pre-seed existing good config to verify rollback restores it.
	good := "# old good config\n"
	if err := os.WriteFile(set.httpConfPath(), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(set.serverConfPath(), []byte(good), 0o644); err != nil {
		t.Fatal(err)
	}

	ng := &mockNginx{testErr: errors.New("nginx: configuration test failed")}
	rs := RuleSet{IPRules: []IPRule{{Action: "deny", CIDR: "9.9.9.9", Enabled: true}}, CC: DefaultCCConfig()}

	_, err := (applier{ng: ng}).apply(set, rs)
	if err == nil {
		t.Fatal("apply must fail when nginx -t fails")
	}
	if ng.reloaded != 0 {
		t.Errorf("reload must not run after failed test, got %d", ng.reloaded)
	}
	// Files must be rolled back to the old good content.
	for _, p := range []string{set.httpConfPath(), set.serverConfPath()} {
		b, _ := os.ReadFile(p)
		if string(b) != good {
			t.Errorf("file %s not rolled back, got:\n%s", filepath.Base(p), b)
		}
	}
}

func TestApplyRollsBackToAbsentWhenNoPriorConfig(t *testing.T) {
	set := testSettings(t)
	ng := &mockNginx{testErr: errors.New("bad config")}
	rs := RuleSet{CC: DefaultCCConfig()}

	if _, err := (applier{ng: ng}).apply(set, rs); err == nil {
		t.Fatal("expected failure")
	}
	// No prior config existed -> rollback removes the newly written files.
	for _, p := range []string{set.httpConfPath(), set.serverConfPath()} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("file %s should be removed on rollback, stat err=%v", filepath.Base(p), err)
		}
	}
}

func TestApplyRejectsBadSettings(t *testing.T) {
	set := DefaultSettings()
	set.ConfigDir = "relative/path" // invalid
	ng := &mockNginx{}
	if _, err := (applier{ng: ng}).apply(set, RuleSet{CC: DefaultCCConfig()}); err == nil {
		t.Fatal("apply must reject invalid settings before writing")
	}
	if ng.tested != 0 {
		t.Error("must not invoke nginx with invalid settings")
	}
}
