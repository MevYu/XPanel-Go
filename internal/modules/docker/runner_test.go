package docker

import "testing"

func TestValidRef(t *testing.T) {
	ok := []string{
		"nginx", "nginx:1.25", "library/nginx:latest", "a1b2c3d4e5f6",
		"ghcr.io/owner/img:tag", "sha256123abc", "img@sha256:deadbeef",
		"my_container-1",
	}
	for _, s := range ok {
		if !ValidRef(s) {
			t.Errorf("ValidRef(%q) = false, want true", s)
		}
	}
	bad := []string{
		"", " ", "a b", "name;rm -rf", "$(whoami)", "a|b", "a&&b",
		"../etc", "name\ninject", "-rm", "`id`", "a>b",
	}
	for _, s := range bad {
		if ValidRef(s) {
			t.Errorf("ValidRef(%q) = true, want false (injection must be rejected)", s)
		}
	}
}

func TestValidProjectName(t *testing.T) {
	ok := []string{"web", "my-app", "app_1", "a"}
	for _, s := range ok {
		if !ValidProjectName(s) {
			t.Errorf("ValidProjectName(%q) = false, want true", s)
		}
	}
	bad := []string{"", "Web", "../x", "a/b", "a b", "a;b", "-app", "app.name"}
	for _, s := range bad {
		if ValidProjectName(s) {
			t.Errorf("ValidProjectName(%q) = true, want false", s)
		}
	}
}

func TestComposeProjectDir(t *testing.T) {
	dir, err := composeProjectDir("/opt/compose", "web")
	if err != nil || dir != "/opt/compose/web" {
		t.Fatalf("got (%q,%v), want /opt/compose/web", dir, err)
	}
	// 非法项目名(含分隔符)被 ValidProjectName 挡掉。
	if _, err := composeProjectDir("/opt/compose", "../etc"); err == nil {
		t.Error("escape attempt should fail")
	}
	if _, err := composeProjectDir("/opt/compose", "a/b"); err == nil {
		t.Error("path separator should fail")
	}
}

func TestClampTail(t *testing.T) {
	cases := map[string]string{
		"":       "200",
		"abc":    "200",
		"0":      "200",
		"-5":     "200",
		"50":     "50",
		"999999": "200",
	}
	for in, want := range cases {
		if got := clampTail(in); got != want {
			t.Errorf("clampTail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseJSONLines(t *testing.T) {
	// 逐行对象(docker ps --format '{{json .}}')
	items, err := parseJSONLines("{\"Id\":\"a\"}\n{\"Id\":\"b\"}\n")
	if err != nil || len(items) != 2 {
		t.Fatalf("line parse: got %d items, err %v", len(items), err)
	}
	// 整体数组(compose ls --format json)
	items, err = parseJSONLines(`[{"Name":"web"}]`)
	if err != nil || len(items) != 1 {
		t.Fatalf("array parse: got %d items, err %v", len(items), err)
	}
	// 空输出 → 空数组,非 nil
	items, err = parseJSONLines("")
	if err != nil || items == nil || len(items) != 0 {
		t.Fatalf("empty: got %v err %v", items, err)
	}
	// 坏 JSON → 错误
	if _, err := parseJSONLines("not json"); err == nil {
		t.Error("invalid JSON should error")
	}
}

func TestValidDir(t *testing.T) {
	ok := []string{"/opt/compose", "/var/lib/docker"}
	for _, s := range ok {
		if !validDir(s) {
			t.Errorf("validDir(%q) = false, want true", s)
		}
	}
	bad := []string{"", "relative/path", "/etc\ninject", " "}
	for _, s := range bad {
		if validDir(s) {
			t.Errorf("validDir(%q) = true, want false", s)
		}
	}
}
