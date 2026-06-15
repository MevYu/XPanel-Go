package java

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderConfigWithJavaPathAndArgs(t *testing.T) {
	cfg := renderConfig(ProcessSpec{
		Name: "web", ArtifactPath: "/www/java/web/app.jar",
		JVMArgs: "-Xms256m -Xmx1g", Port: 8080,
		JavaPath: "/usr/lib/jvm/jdk17/bin", LogDir: "/var/log/java",
	})
	for _, want := range []string{
		"[program:web]",
		"command=/usr/lib/jvm/jdk17/bin/java -Xms256m -Xmx1g -jar /www/java/web/app.jar",
		"directory=/www/java/web",
		`SERVER_PORT="8080"`,
		"/usr/lib/jvm/jdk17/bin:%(ENV_PATH)s",
		"stdout_logfile=/var/log/java/web.out.log",
		"stderr_logfile=/var/log/java/web.err.log",
		"autorestart=true",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered config missing %q:\n%s", want, cfg)
		}
	}
}

func TestRenderConfigWithoutJavaPathOrArgs(t *testing.T) {
	cfg := renderConfig(ProcessSpec{
		Name: "web", ArtifactPath: "/d/app.jar", Port: 8080, LogDir: "/l",
	})
	if strings.Contains(cfg, ":%(ENV_PATH)s") {
		t.Errorf("no JavaPath should not prefix PATH:\n%s", cfg)
	}
	if !strings.Contains(cfg, "command=java -jar /d/app.jar") {
		t.Errorf("expected bare java command:\n%s", cfg)
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

func TestSafeWebappPathRejectsBadName(t *testing.T) {
	if _, err := safeWebappPath("/opt/tomcat", "../evil"); err == nil {
		t.Error("expected bad name rejected")
	}
	p, err := safeWebappPath("/opt/tomcat", "web")
	if err != nil || p != "/opt/tomcat/webapps/web.war" {
		t.Fatalf("got %q err %v", p, err)
	}
}

func TestActionRejectsBadVerb(t *testing.T) {
	if _, err := NewSupervisorManager().Action("kill", "web"); err == nil {
		t.Error("expected disallowed verb rejected")
	}
}

func TestParseJavaVersion(t *testing.T) {
	out := "openjdk version \"17.0.9\" 2023-10-17\nOpenJDK Runtime Environment"
	if got := parseJavaVersion(out); got != "17.0.9" {
		t.Errorf("got %q want 17.0.9", got)
	}
	if got := parseJavaVersion("no version here"); got != "" {
		t.Errorf("got %q want empty", got)
	}
}

func TestDeployUndeployRoundTrip(t *testing.T) {
	tomcat := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tomcat, "webapps"), 0o755); err != nil {
		t.Fatal(err)
	}
	war := filepath.Join(t.TempDir(), "src.war")
	if err := os.WriteFile(war, []byte("PK-war-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	pm := NewSupervisorManager()
	if err := pm.Deploy(tomcat, "myapp", war); err != nil {
		t.Fatalf("deploy: %v", err)
	}
	dst := filepath.Join(tomcat, "webapps", "myapp.war")
	if b, err := os.ReadFile(dst); err != nil || string(b) != "PK-war-bytes" {
		t.Fatalf("war not copied: %v %q", err, b)
	}
	// 模拟 Tomcat 解包目录。
	if err := os.MkdirAll(filepath.Join(tomcat, "webapps", "myapp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := pm.Undeploy(tomcat, "myapp"); err != nil {
		t.Fatalf("undeploy: %v", err)
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Error("war should be removed")
	}
	if _, err := os.Stat(filepath.Join(tomcat, "webapps", "myapp")); !os.IsNotExist(err) {
		t.Error("exploded dir should be removed")
	}
}
