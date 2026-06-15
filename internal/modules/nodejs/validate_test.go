package nodejs

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

func TestValidNodeVersion(t *testing.T) {
	good := []string{"", "system", "18", "18.19", "18.19.0", "v20", "v20.1.0"}
	for _, v := range good {
		if !ValidNodeVersion(v) {
			t.Errorf("expected %q valid", v)
		}
	}
	bad := []string{"latest", "18; rm", "node18", "../18", "18.x", "v"}
	for _, v := range bad {
		if ValidNodeVersion(v) {
			t.Errorf("expected %q invalid", v)
		}
	}
}

func TestValidStartCommand(t *testing.T) {
	if !ValidStartCommand("node app.js") || !ValidStartCommand("npm run start") {
		t.Error("expected normal commands valid")
	}
	bad := []string{"", "  ", "node app.js\nmalicious=1", "node\tapp", "a\rb"}
	for _, c := range bad {
		if ValidStartCommand(c) {
			t.Errorf("expected %q invalid", c)
		}
	}
}

func TestValidPort(t *testing.T) {
	if !ValidPort(1) || !ValidPort(3000) || !ValidPort(65535) {
		t.Error("valid ports rejected")
	}
	if ValidPort(0) || ValidPort(-1) || ValidPort(65536) {
		t.Error("invalid ports accepted")
	}
}

func TestSafeProjectDirRelative(t *testing.T) {
	got, err := safeProjectDir("/www/nodejs", "myapp")
	if err != nil || got != "/www/nodejs/myapp" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSafeProjectDirAbsoluteInside(t *testing.T) {
	got, err := safeProjectDir("/www/nodejs", "/www/nodejs/api")
	if err != nil || got != "/www/nodejs/api" {
		t.Fatalf("got %q err %v", got, err)
	}
}

func TestSafeProjectDirRejectsEscape(t *testing.T) {
	bad := []string{"../etc", "/etc/passwd", "../../root", "ok/../../escape"}
	for _, d := range bad {
		if _, err := safeProjectDir("/www/nodejs", d); err == nil {
			t.Errorf("expected escape rejected for %q", d)
		}
	}
}

func TestSettingsValidate(t *testing.T) {
	if err := DefaultSettings().validate(); err != nil {
		t.Fatalf("defaults must validate: %v", err)
	}
	bad := Settings{BaseDir: "relative", NodeDir: "/a", ConfDir: "/b", LogDir: "/c"}
	if err := bad.validate(); err == nil {
		t.Error("relative base_dir must be rejected")
	}
	inj := Settings{BaseDir: "/www/n; rm", NodeDir: "/a", ConfDir: "/b", LogDir: "/c"}
	if err := inj.validate(); err == nil {
		t.Error("base_dir with shell metachar must be rejected")
	}
}
