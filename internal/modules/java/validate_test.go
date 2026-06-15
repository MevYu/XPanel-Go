package java

import "testing"

func TestValidProjectName(t *testing.T) {
	good := []string{"app", "my-app", "api_v2", "web.1", "A1"}
	for _, n := range good {
		if !ValidProjectName(n) {
			t.Errorf("expected %q valid", n)
		}
	}
	bad := []string{"", ".", "..", "a/b", "a b", "a;rm", "-leading", "a\nb", "../x", "a..b", "a/../b"}
	for _, n := range bad {
		if ValidProjectName(n) {
			t.Errorf("expected %q invalid", n)
		}
	}
}

func TestValidJavaVersion(t *testing.T) {
	good := []string{"", "system", "8", "11", "17", "21", "1.8", "17.0.9"}
	for _, v := range good {
		if !ValidJavaVersion(v) {
			t.Errorf("expected %q valid", v)
		}
	}
	bad := []string{"latest", "17; rm", "jdk17", "../17", "17.x", "v17"}
	for _, v := range bad {
		if ValidJavaVersion(v) {
			t.Errorf("expected %q invalid", v)
		}
	}
}

func TestValidProjectType(t *testing.T) {
	for _, ty := range []string{"jar", "war", "tomcat"} {
		if !ValidProjectType(ty) {
			t.Errorf("expected %q valid", ty)
		}
	}
	for _, ty := range []string{"", "exe", "JAR", "jar;rm", "sh"} {
		if ValidProjectType(ty) {
			t.Errorf("expected %q invalid", ty)
		}
	}
}

func TestValidJVMArgs(t *testing.T) {
	good := []string{"", "-Xmx512m", "-Xms256m -Xmx1g -Dspring.profiles.active=prod"}
	for _, a := range good {
		if !ValidJVMArgs(a) {
			t.Errorf("expected %q valid", a)
		}
	}
	bad := []string{"-Xmx512m\nmalicious=1", "-Xmx1g; rm -rf /", "-Dx=$(whoami)", "-Dx=`id`", "a|b", "a&b", "a>b"}
	for _, a := range bad {
		if ValidJVMArgs(a) {
			t.Errorf("expected %q invalid", a)
		}
	}
}

func TestSplitArgs(t *testing.T) {
	got := splitArgs("-Xms256m  -Xmx1g -Dk=v")
	want := []string{"-Xms256m", "-Xmx1g", "-Dk=v"}
	if len(got) != len(want) {
		t.Fatalf("got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v want %v", got, want)
		}
	}
	if len(splitArgs("")) != 0 {
		t.Error("empty args must split to empty slice")
	}
}

func TestValidPort(t *testing.T) {
	if !ValidPort(1) || !ValidPort(8080) || !ValidPort(65535) {
		t.Error("valid ports rejected")
	}
	if ValidPort(0) || ValidPort(-1) || ValidPort(65536) {
		t.Error("invalid ports accepted")
	}
}

func TestSafeArtifactPathRelative(t *testing.T) {
	got, err := safeArtifactPath("/www/java", "app/app.jar", ".jar")
	if err != nil || got != "/www/java/app/app.jar" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSafeArtifactPathAbsoluteInside(t *testing.T) {
	got, err := safeArtifactPath("/www/java", "/www/java/api.war", ".war")
	if err != nil || got != "/www/java/api.war" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSafeArtifactPathRejectsEscape(t *testing.T) {
	bad := []string{"../etc/x.jar", "/etc/passwd", "../../root/a.jar", "ok/../../escape.jar"}
	for _, d := range bad {
		if _, err := safeArtifactPath("/www/java", d, ".jar"); err == nil {
			t.Errorf("expected escape rejected for %q", d)
		}
	}
}

func TestSafeArtifactPathRejectsWrongSuffix(t *testing.T) {
	if _, err := safeArtifactPath("/www/java", "app/app.sh", ".jar"); err == nil {
		t.Error("expected wrong suffix rejected")
	}
}

func TestSettingsValidate(t *testing.T) {
	if err := DefaultSettings().validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	bad := Settings{BaseDir: "relative", JDKDir: "/a", TomcatDir: "/b", ConfDir: "/c", LogDir: "/d"}
	if err := bad.validate(); err == nil {
		t.Error("relative base_dir must be rejected")
	}
	inj := Settings{BaseDir: "/www/j; rm", JDKDir: "/a", TomcatDir: "/b", ConfDir: "/c", LogDir: "/d"}
	if err := inj.validate(); err == nil {
		t.Error("base_dir with shell metachar must be rejected")
	}
}
