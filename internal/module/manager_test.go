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

type startFailModule struct{ fakeModule }

func (startFailModule) Start(Context) error { return errors.New("start boom") }
func (startFailModule) HealthCheck() error  { return nil }

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

// HealthCheck 失败不再挡住启用:模块照常启用并启动,只把健康状态记成降级(ok=false + reason)。
func TestEnableHealthCheckDegradedButEnabled(t *testing.T) {
	m := &startStopModule{fakeModule: fakeModule{id: "svc"}, healthErr: errors.New("systemctl not found")}
	mgr, st := newManager(t, m)
	defer st.Close()
	if err := mgr.Enable("svc"); err != nil {
		t.Fatalf("Enable should succeed despite failed health check: %v", err)
	}
	if !mgr.IsEnabled("svc") {
		t.Error("module should be enabled even with failed health check")
	}
	if !m.started {
		t.Error("module should be started even with failed health check")
	}
	enabled, _ := st.EnabledModules()
	if !enabled["svc"] {
		t.Error("enabled state should persist despite failed health check")
	}
	h := mgr.Health("svc")
	if h.OK {
		t.Error("health.OK should be false after failed health check")
	}
	if h.Reason != "systemctl not found" {
		t.Errorf("health.Reason = %q, want %q", h.Reason, "systemctl not found")
	}
}

func TestEnableHealthyRecordsOK(t *testing.T) {
	m := &startStopModule{fakeModule: fakeModule{id: "svc"}}
	mgr, st := newManager(t, m)
	defer st.Close()
	if err := mgr.Enable("svc"); err != nil {
		t.Fatalf("Enable: %v", err)
	}
	if h := mgr.Health("svc"); !h.OK || h.Reason != "" {
		t.Errorf("healthy module should have OK=true reason=\"\", got %+v", h)
	}
}

// Start 失败仍是真错误:拒绝启用并回滚(HealthCheck 降级不影响这条)。
func TestEnableStartFailureStillRejected(t *testing.T) {
	m := &startFailModule{fakeModule: fakeModule{id: "svc"}}
	mgr, st := newManager(t, m)
	defer st.Close()
	if err := mgr.Enable("svc"); err == nil {
		t.Error("Enable should fail when Start fails")
	}
	if mgr.IsEnabled("svc") {
		t.Error("module must not be enabled after Start failure")
	}
	enabled, _ := st.EnabledModules()
	if enabled["svc"] {
		t.Error("enabled state must not persist after Start failure")
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
