package module

import (
	"errors"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

type startStopModule struct {
	fakeModule
	started   bool
	healthErr error
}

func (m *startStopModule) Start(Context) error { m.started = true; return nil }
func (m *startStopModule) Stop(Context) error  { m.started = false; return nil }
func (m *startStopModule) HealthCheck() error  { return m.healthErr }

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
	if err := mgr.Enable("svc"); err == nil {
		t.Error("Enable should fail when HealthCheck fails")
	}
	if mgr.IsEnabled("svc") {
		t.Error("module must not be enabled after failed health check")
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
