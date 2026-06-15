package php

import (
	"path/filepath"
	"testing"
)

func TestDefaultSettingsValid(t *testing.T) {
	if err := DefaultSettings().Validate(); err != nil {
		t.Fatalf("default settings must validate: %v", err)
	}
	if DefaultSettings().InstallBase != "/www/server/php" {
		t.Errorf("unexpected default install base: %q", DefaultSettings().InstallBase)
	}
}

func TestSettingsValidateRejectsBadPaths(t *testing.T) {
	cases := []Settings{
		{InstallBase: "relative/php", FpmConfDir: "/a", FpmSockDir: "/b", FpmUnitTemplate: "php%s-fpm"},
		{InstallBase: "/www/../etc", FpmConfDir: "/a", FpmSockDir: "/b", FpmUnitTemplate: "php%s-fpm"},
		{InstallBase: "/ok\n", FpmConfDir: "/a", FpmSockDir: "/b", FpmUnitTemplate: "php%s-fpm"},
		{InstallBase: "/ok", FpmConfDir: "/a", FpmSockDir: "/b", FpmUnitTemplate: "php%s-fpm; rm"},
		{InstallBase: "/ok", FpmConfDir: "/a", FpmSockDir: "/b", FpmUnitTemplate: "no-placeholder"},
		{InstallBase: "/ok", FpmConfDir: "/a", FpmSockDir: "/b", FpmUnitTemplate: ""},
	}
	for i, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("case %d: expected validation error, got nil for %+v", i, c)
		}
	}
}

func TestSettingsPathDerivation(t *testing.T) {
	s := DefaultSettings()
	if got, want := s.phpBin("8.1"), filepath.Join("/www/server/php", "8.1", "bin", "php"); got != want {
		t.Errorf("phpBin = %q, want %q", got, want)
	}
	if got, want := s.iniPath("8.1"), filepath.Join("/www/server/php", "8.1", "etc", "php.ini"); got != want {
		t.Errorf("iniPath = %q, want %q", got, want)
	}
	if got, want := s.fpmUnit("8.1"), "php-fpm-8.1"; got != want {
		t.Errorf("fpmUnit = %q, want %q", got, want)
	}
}
