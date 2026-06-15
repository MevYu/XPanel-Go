package supervisor

import (
	"strings"
	"testing"
)

func TestValidProgramName(t *testing.T) {
	good := []string{"app", "my-worker", "queue_1", "a.b", strings.Repeat("a", 64)}
	for _, n := range good {
		if !ValidProgramName(n) {
			t.Errorf("expected %q valid", n)
		}
	}
	bad := []string{"", ".", "..", "a/b", "a b", "a;rm", "a$(x)", "a\n", "../etc", strings.Repeat("a", 65), "app&"}
	for _, n := range bad {
		if ValidProgramName(n) {
			t.Errorf("expected %q invalid", n)
		}
	}
}

func TestValidCommand(t *testing.T) {
	if !ValidCommand("/usr/bin/python3 app.py --flag") {
		t.Error("normal command should be valid")
	}
	for _, c := range []string{"", "   ", "cmd\nrm -rf /", "cmd\rfoo", "cmd\x00"} {
		if ValidCommand(c) {
			t.Errorf("expected %q invalid", c)
		}
	}
}

func TestValidDir(t *testing.T) {
	if !ValidDir("/opt/app") {
		t.Error("absolute dir should be valid")
	}
	for _, d := range []string{"", "relative/path", "../up", "/opt\napp"} {
		if ValidDir(d) {
			t.Errorf("expected %q invalid", d)
		}
	}
}

func TestValidNumprocs(t *testing.T) {
	for _, n := range []int{1, 4, 256} {
		if !ValidNumprocs(n) {
			t.Errorf("expected %d valid", n)
		}
	}
	for _, n := range []int{0, -1, 257, 1000} {
		if ValidNumprocs(n) {
			t.Errorf("expected %d invalid", n)
		}
	}
}

func TestRenderConfigSingleProc(t *testing.T) {
	cfg := RenderConfig(ProgramSpec{
		Name: "web", Command: "/bin/run", Directory: "/opt/web",
		AutoRestart: true, Numprocs: 1, LogDir: "/var/log/supervisor",
	})
	want := []string{
		"[program:web]",
		"command=/bin/run",
		"directory=/opt/web",
		"autostart=true",
		"autorestart=true",
		"numprocs=1",
		"stdout_logfile=/var/log/supervisor/web.out.log",
		"stderr_logfile=/var/log/supervisor/web.err.log",
	}
	for _, line := range want {
		if !strings.Contains(cfg, line) {
			t.Errorf("config missing %q\n--- got ---\n%s", line, cfg)
		}
	}
	if strings.Contains(cfg, "process_name=") {
		t.Errorf("single-proc config must not set process_name\n%s", cfg)
	}
}

func TestRenderConfigMultiProc(t *testing.T) {
	cfg := RenderConfig(ProgramSpec{
		Name: "worker", Command: "/bin/work", Directory: "/opt",
		AutoRestart: false, Numprocs: 4, LogDir: "/var/log/supervisor/",
	})
	if !strings.Contains(cfg, "numprocs=4") {
		t.Errorf("missing numprocs=4\n%s", cfg)
	}
	if !strings.Contains(cfg, "process_name=%(program_name)s_%(process_num)02d") {
		t.Errorf("multi-proc must set process_name\n%s", cfg)
	}
	if !strings.Contains(cfg, "autorestart=false") {
		t.Errorf("autorestart should be false\n%s", cfg)
	}
	// LogDir trailing slash must be normalized (no double slash).
	if strings.Contains(cfg, "//worker") {
		t.Errorf("log dir trailing slash not normalized\n%s", cfg)
	}
}

func TestSafeConfPathRejectsTraversal(t *testing.T) {
	// 名称已过白名单,这里确认词法兜底仍把路径锁在 confDir。
	if _, err := safeConfPath("/etc/supervisor/conf.d", "ok-name"); err != nil {
		t.Errorf("valid name should produce path, got %v", err)
	}
	if _, err := safeConfPath("/etc/supervisor/conf.d", "../evil"); err == nil {
		t.Error("traversal name must be rejected")
	}
}
