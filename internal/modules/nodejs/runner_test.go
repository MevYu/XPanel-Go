package nodejs

import (
	"strings"
	"testing"
)

func TestRenderConfigWithNodePath(t *testing.T) {
	cfg := renderConfig(ProcessSpec{
		Name: "web", Directory: "/www/nodejs/web", Command: "node app.js",
		Port: 3000, NodePath: "/opt/node/bin", LogDir: "/var/log/node",
	})
	for _, want := range []string{
		"[program:web]",
		"command=node app.js",
		"directory=/www/nodejs/web",
		`PORT="3000"`,
		"/opt/node/bin:%(ENV_PATH)s",
		"stdout_logfile=/var/log/node/web.out.log",
		"stderr_logfile=/var/log/node/web.err.log",
		"autorestart=true",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered config missing %q:\n%s", want, cfg)
		}
	}
}

func TestRenderConfigWithoutNodePath(t *testing.T) {
	cfg := renderConfig(ProcessSpec{
		Name: "web", Directory: "/d", Command: "npm start", Port: 8080, LogDir: "/l",
	})
	if strings.Contains(cfg, ":%(ENV_PATH)s") {
		t.Errorf("no NodePath should not prefix PATH:\n%s", cfg)
	}
	if !strings.Contains(cfg, `PATH="%(ENV_PATH)s"`) {
		t.Errorf("expected bare ENV_PATH:\n%s", cfg)
	}
}

func TestSafeConfPathRejectsBadName(t *testing.T) {
	if _, err := safeConfPath("/etc/supervisor/conf.d", "../evil"); err == nil {
		t.Error("expected bad name rejected")
	}
	p, err := safeConfPath("/etc/supervisor/conf.d", "web")
	if err != nil || p != "/etc/supervisor/conf.d/web.conf" {
		t.Fatalf("got %q err %v", p, err)
	}
}

func TestActionRejectsBadVerb(t *testing.T) {
	if _, err := NewSupervisorManager().Action("kill", "web"); err == nil {
		t.Error("expected disallowed verb rejected")
	}
}
