package python

import (
	"strings"
	"testing"
)

func TestValidProjectName(t *testing.T) {
	good := []string{"app", "my-api", "site_1", "a.b", strings.Repeat("a", 64)}
	for _, n := range good {
		if !ValidProjectName(n) {
			t.Errorf("expected %q valid", n)
		}
	}
	bad := []string{"", ".", "..", "a/b", "a b", "a;rm", "a$(x)", "a\n", "../etc", strings.Repeat("a", 65), "app&"}
	for _, n := range bad {
		if ValidProjectName(n) {
			t.Errorf("expected %q invalid", n)
		}
	}
}

func TestValidPythonVersion(t *testing.T) {
	for _, v := range []string{"python3", "python3.11", "3.11", "3", "python3.9"} {
		if !ValidPythonVersion(v) {
			t.Errorf("expected %q valid", v)
		}
	}
	for _, v := range []string{"", "2.7", "python2", "3.11; rm", "/usr/bin/python", "python3.111", "py"} {
		if ValidPythonVersion(v) {
			t.Errorf("expected %q invalid", v)
		}
	}
}

func TestValidStartKind(t *testing.T) {
	for _, k := range []string{"gunicorn", "uvicorn", "script"} {
		if !ValidStartKind(k) {
			t.Errorf("expected %q valid", k)
		}
	}
	for _, k := range []string{"", "flask", "node", "GUNICORN"} {
		if ValidStartKind(k) {
			t.Errorf("expected %q invalid", k)
		}
	}
}

func TestValidPort(t *testing.T) {
	for _, p := range []int{1, 8000, 65535} {
		if !ValidPort(p) {
			t.Errorf("expected %d valid", p)
		}
	}
	for _, p := range []int{0, -1, 65536, 100000} {
		if ValidPort(p) {
			t.Errorf("expected %d invalid", p)
		}
	}
}

func TestValidAppTarget(t *testing.T) {
	for _, target := range []string{"app:application", "wsgi:app", "main.py", "src/server.py", "package.module:app"} {
		if !ValidAppTarget(target) {
			t.Errorf("expected %q valid", target)
		}
	}
	bad := []string{"", "app app", "app;rm", "app$(x)", "/abs/path:app", "../escape:app", "a\nb", strings.Repeat("a", 129)}
	for _, target := range bad {
		if ValidAppTarget(target) {
			t.Errorf("expected %q invalid", target)
		}
	}
}

func TestValidDir(t *testing.T) {
	if !ValidDir("/www/python/app") {
		t.Error("absolute dir should be valid")
	}
	for _, d := range []string{"", "relative/path", "../up", "/www\napp"} {
		if ValidDir(d) {
			t.Errorf("expected %q invalid", d)
		}
	}
}

func TestBuildCommandGunicorn(t *testing.T) {
	argv := BuildCommand(ProjectSpec{
		Name: "api", VenvDir: "/www/python/api/venv", StartKind: StartGunicorn,
		AppTarget: "wsgi:app", Port: 8000, Workers: 3,
	})
	want := []string{"/www/python/api/venv/bin/gunicorn", "--workers", "3", "--bind", "0.0.0.0:8000", "wsgi:app"}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("gunicorn argv mismatch:\n got %v\nwant %v", argv, want)
	}
}

func TestBuildCommandUvicorn(t *testing.T) {
	argv := BuildCommand(ProjectSpec{
		Name: "api", VenvDir: "/v", StartKind: StartUvicorn,
		AppTarget: "main:app", Port: 9000, Workers: 0,
	})
	joined := strings.Join(argv, " ")
	if !strings.Contains(joined, "/v/bin/uvicorn") || !strings.Contains(joined, "--port 9000") ||
		!strings.Contains(joined, "--workers 1") || !strings.HasSuffix(joined, "main:app") {
		t.Fatalf("uvicorn argv wrong: %v", argv)
	}
}

func TestBuildCommandScript(t *testing.T) {
	argv := BuildCommand(ProjectSpec{
		Name: "job", VenvDir: "/v", StartKind: StartScript, AppTarget: "run.py",
	})
	want := []string{"/v/bin/python", "run.py"}
	if strings.Join(argv, " ") != strings.Join(want, " ") {
		t.Fatalf("script argv mismatch: got %v want %v", argv, want)
	}
}

func TestRenderSupervisorConfig(t *testing.T) {
	argv := []string{"/v/bin/gunicorn", "--bind", "0.0.0.0:8000", "wsgi:app"}
	cfg := renderSupervisorConfig("api", "/www/python/api", argv, "/var/log/xpanel-python/")
	for _, line := range []string{
		"[program:api]",
		"command=/v/bin/gunicorn --bind 0.0.0.0:8000 wsgi:app",
		"directory=/www/python/api",
		"autostart=true",
		"stdout_logfile=/var/log/xpanel-python/api.out.log",
	} {
		if !strings.Contains(cfg, line) {
			t.Errorf("config missing %q\n--- got ---\n%s", line, cfg)
		}
	}
	if strings.Contains(cfg, "//api") {
		t.Errorf("trailing slash not normalized\n%s", cfg)
	}
}

func TestSafeConfPathRejectsTraversal(t *testing.T) {
	if _, err := safeConfPath("/etc/supervisor/conf.d", "ok-name"); err != nil {
		t.Errorf("valid name should produce path, got %v", err)
	}
	if _, err := safeConfPath("/etc/supervisor/conf.d", "../evil"); err == nil {
		t.Error("traversal name must be rejected")
	}
}
