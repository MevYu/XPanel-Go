package store

import "testing"

func TestModuleStateSetAndList(t *testing.T) {
	s, _ := Open(":memory:")
	defer s.Close()

	if err := s.SetModuleEnabled("service", true); err != nil {
		t.Fatalf("SetModuleEnabled: %v", err)
	}
	enabled, err := s.EnabledModules()
	if err != nil {
		t.Fatalf("EnabledModules: %v", err)
	}
	if len(enabled) != 1 || !enabled["service"] {
		t.Errorf("want {service:true}, got %v", enabled)
	}

	if err := s.SetModuleEnabled("service", false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	enabled, _ = s.EnabledModules()
	if enabled["service"] {
		t.Error("service should be disabled after set false")
	}
}
