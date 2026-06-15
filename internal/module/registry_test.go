package module

import "testing"

type fakeModule struct {
	id       string
	requires []string
	alwaysOn bool
}

func (f fakeModule) Meta() ModuleMeta {
	return ModuleMeta{ID: f.id, Name: f.id, Category: "test", Requires: f.requires, AlwaysOn: f.alwaysOn}
}
func (f fakeModule) Routes(Router)       {}
func (f fakeModule) Nav() []NavItem      { return nil }
func (f fakeModule) Start(Context) error { return nil }
func (f fakeModule) Stop(Context) error  { return nil }
func (f fakeModule) HealthCheck() error  { return nil }

func TestRegistryRegisterAndGet(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeModule{id: "alpha"})
	if got, ok := r.Get("alpha"); !ok || got.Meta().ID != "alpha" {
		t.Fatalf("Get(alpha) failed: ok=%v", ok)
	}
	if _, ok := r.Get("missing"); ok {
		t.Error("Get(missing) should be false")
	}
	if len(r.All()) != 1 {
		t.Errorf("All() len = %d, want 1", len(r.All()))
	}
}

func TestRegistryRejectsDuplicate(t *testing.T) {
	r := NewRegistry()
	r.Register(fakeModule{id: "dup"})
	defer func() {
		if recover() == nil {
			t.Error("duplicate Register should panic")
		}
	}()
	r.Register(fakeModule{id: "dup"})
}
