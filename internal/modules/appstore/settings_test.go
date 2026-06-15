package appstore

import "testing"

func TestDefaultSettingsValid(t *testing.T) {
	if err := DefaultSettings().validate(); err != nil {
		t.Fatalf("default settings must be valid: %v", err)
	}
}

func TestSettingsValidateRejectsBadPaths(t *testing.T) {
	cases := []Settings{
		{AppsRoot: "relative", ProjectDir: "/opt/x"},
		{AppsRoot: "/opt/../etc", ProjectDir: "/opt/x"},
		{AppsRoot: "/opt/x", ProjectDir: "/opt/a b"},
		{AppsRoot: "/opt/x", ProjectDir: ""},
	}
	for _, s := range cases {
		if err := s.validate(); err == nil {
			t.Errorf("settings %+v should be invalid", s)
		}
	}
}
