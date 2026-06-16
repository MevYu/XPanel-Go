package migration

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidToolPath_SimpleNames(t *testing.T) {
	ok := []string{"", "mysqldump", "pg_dump", "mysql", "psql", "mariadb-dump", "mysql.real", "tool-1.2"}
	for _, v := range ok {
		if !validToolPath(v) {
			t.Errorf("validToolPath(%q) = false, want true", v)
		}
	}
}

func TestValidToolPath_RejectsInjection(t *testing.T) {
	bad := []string{
		"mysql; rm -rf /",
		"mysql && evil",
		"mysql evil",
		"my sql",
		"../bin/mysql",
		"./mysql",
		"sub/mysql",
		"$(id)",
		"mysql\nx",
		"mysql|cat",
		"/tmp/evil",             // absolute but not under trusted dir
		"/home/user/evil",       // untrusted dir
		"relative/../../escape", // not absolute, has slashes
	}
	for _, v := range bad {
		if validToolPath(v) {
			t.Errorf("validToolPath(%q) = true, want false", v)
		}
	}
}

func TestValidToolPath_TrustedAbsoluteExisting(t *testing.T) {
	// An absolute path under a trusted dir that exists is allowed.
	// Use a real binary likely present; fall back to creating one under a trusted dir is
	// not possible (trusted dirs are system dirs), so probe common locations.
	candidates := []string{"/bin/sh", "/usr/bin/env", "/bin/ls", "/usr/bin/true"}
	var found string
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			found = c
			break
		}
	}
	if found == "" {
		t.Skip("no trusted-dir binary available to probe")
	}
	if !validToolPath(found) {
		t.Errorf("validToolPath(%q) = false, want true (trusted existing absolute)", found)
	}
}

func TestValidToolPath_TrustedAbsoluteNonExisting(t *testing.T) {
	// Absolute path under a trusted dir but the file does not exist -> rejected.
	p := filepath.Join("/usr/bin", "definitely-not-a-real-binary-xyz-12345")
	if _, err := os.Stat(p); err == nil {
		t.Skip("probe file unexpectedly exists")
	}
	if validToolPath(p) {
		t.Errorf("validToolPath(%q) = true, want false (nonexistent under trusted dir)", p)
	}
}
