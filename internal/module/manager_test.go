package module

import (
	"errors"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

type startStopModule struct {
	fakeModule
	started   bool
	healthErr error
	startErr  error
}

func (m *startStopModule) Start(Context) error {
	if m.startErr != nil {
		return m.startErr
	}
	m.started = true
	return nil
}
func (m *startStopModule) Stop(Context) error { m.started = false; return nil }
func (m *startStopModule) HealthCheck() error { return m.healthErr }

func newManager(t *testing.T, mods ...Module) (*Manager, *store.Store) {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	reg := NewRegistry()
	for _, m := range mods {
		reg.Register(m)
	}
	return NewManager(reg, st), st
}

func TestEnableStartsModuleAndPersists(t *testing.T) {
	m := &startStopModule{fakeModule: fakeModule{id: "svc"}}
	mgr, st := newManager(t, m)
	defer st.Close()

	if err := mgr.Enable("svc"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if !m.started {
		t.Error("module should be started")
	}
	if !mgr.IsEnabled("svc") {
		t.Error("manager should report enabled")
	}
	enabled, _ := st.EnabledModules()
	if !enabled["svc"] {
		t.Error("enabled state should persist")
	}
}

func TestEnableFailsHealthCheck(t *testing.T) {
	m := &startStopModule{fakeModule: fakeModule{id: "svc"}, healthErr: errors.New("systemctl missing")}
	mgr, st := newManager(t, m)
	defer st.Close()
	err := mgr.Enable("svc")
	if err == nil {
		t.Fatal("Enable should fail when HealthCheck fails")
	}
	// HealthCheck 失败原因对用户可见、可操作 → 必须是 ValidationError 且携带原文。
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("HealthCheck failure should be a *ValidationError, got %T: %v", err, err)
	}
	if !strings.Contains(ve.Msg, "systemctl missing") {
		t.Errorf("HealthCheck reason should be carried in message, got %q", ve.Msg)
	}
	if mgr.IsEnabled("svc") {
		t.Error("module must not be enabled after failed health check")
	}
}

func TestEnableStartFailureNotValidationError(t *testing.T) {
	// Start 失败是真正的内部错误,不得包成 ValidationError(否则会被 handler 放给前端)。
	m := &startStopModule{fakeModule: fakeModule{id: "svc"}, startErr: errors.New("/secret start boom")}
	mgr, st := newManager(t, m)
	defer st.Close()
	err := mgr.Enable("svc")
	if err == nil {
		t.Fatal("Enable should fail when Start fails")
	}
	var ve *ValidationError
	if errors.As(err, &ve) {
		t.Errorf("Start failure must not be a *ValidationError, got %q", ve.Msg)
	}
	if mgr.IsEnabled("svc") {
		t.Error("module must not be enabled after failed start")
	}
}

func TestEnableRequiresDependency(t *testing.T) {
	dep := &startStopModule{fakeModule: fakeModule{id: "base"}}
	child := &startStopModule{fakeModule: fakeModule{id: "child", requires: []string{"base"}}}
	mgr, st := newManager(t, dep, child)
	defer st.Close()

	if err := mgr.Enable("child"); err == nil {
		t.Error("enabling child before base should fail")
	}
	if err := mgr.Enable("base"); err != nil {
		t.Fatalf("enable base: %v", err)
	}
	if err := mgr.Enable("child"); err != nil {
		t.Errorf("enable child after base should succeed: %v", err)
	}
}

func TestDisableBlockedByDependent(t *testing.T) {
	dep := &startStopModule{fakeModule: fakeModule{id: "base"}}
	child := &startStopModule{fakeModule: fakeModule{id: "child", requires: []string{"base"}}}
	mgr, st := newManager(t, dep, child)
	defer st.Close()
	mgr.Enable("base")
	mgr.Enable("child")
	if err := mgr.Disable("base"); err == nil {
		t.Error("disabling base while child enabled should fail")
	}
}

func TestRestoreOrderIndependent(t *testing.T) {
	// 注册顺序故意把 child 放在 base 之前,验证 Restore 不依赖注册顺序。
	base := &startStopModule{fakeModule: fakeModule{id: "base"}}
	child := &startStopModule{fakeModule: fakeModule{id: "child", requires: []string{"base"}}}
	mgr, st := newManager(t, child, base)
	defer st.Close()

	if err := st.SetModuleEnabled("base", true); err != nil {
		t.Fatalf("persist base: %v", err)
	}
	if err := st.SetModuleEnabled("child", true); err != nil {
		t.Fatalf("persist child: %v", err)
	}

	if err := mgr.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !mgr.IsEnabled("base") || !base.started {
		t.Error("base should be enabled+started after Restore")
	}
	if !mgr.IsEnabled("child") || !child.started {
		t.Error("child should be enabled+started after Restore")
	}
}

func TestAlwaysOnEnabledOnRestore(t *testing.T) {
	always := &startStopModule{fakeModule: fakeModule{id: "dash", alwaysOn: true}}
	mgr, st := newManager(t, always)
	defer st.Close()
	if err := mgr.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if !mgr.IsEnabled("dash") || !always.started {
		t.Error("AlwaysOn module should be enabled+started after Restore")
	}
}
