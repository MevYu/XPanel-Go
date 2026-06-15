package php

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDetectVersions(t *testing.T) {
	base := t.TempDir()
	for _, d := range []string{"8.1", "7.4", "notaversion", "8.2.1"} {
		if err := os.MkdirAll(filepath.Join(base, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// 一个文件(非目录)不应被当作版本。
	if err := os.WriteFile(filepath.Join(base, "9.9"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got := detectVersions(base)
	want := []string{"7.4", "8.1", "8.2.1"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detectVersions = %v, want %v", got, want)
	}
}

func TestDetectVersionsMissingDir(t *testing.T) {
	if got := detectVersions("/nonexistent/php/base"); got != nil {
		t.Errorf("missing dir must yield nil, got %v", got)
	}
}

func TestParseModules(t *testing.T) {
	raw := "[PHP Modules]\nCore\nopcache\npdo_mysql\n\n[Zend Modules]\nZend OPcache"
	got := parseModules(raw)
	want := []string{"Core", "opcache", "pdo_mysql"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("parseModules = %v, want %v", got, want)
	}
}
