package waf

import "testing"

func TestDefaultSettingsValid(t *testing.T) {
	if err := DefaultSettings().Validate(); err != nil {
		t.Fatalf("default settings must be valid: %v", err)
	}
}

func TestSettingsValidate(t *testing.T) {
	base := DefaultSettings()

	bad := []Settings{
		func() Settings { s := base; s.ConfigDir = "etc/nginx/waf"; return s }(),     // not absolute
		func() Settings { s := base; s.ConfigDir = "/etc/../etc/nginx"; return s }(), // not clean
		func() Settings { s := base; s.ConfigDir = "/etc/nginx\n"; return s }(),      // newline
		func() Settings { s := base; s.HTTPConfName = "a/b.conf"; return s }(),       // slash in name
		func() Settings { s := base; s.HTTPConfName = ".."; return s }(),             // dotdot name
		func() Settings { s := base; s.ServerConfName = ""; return s }(),             // empty name
		func() Settings { s := base; s.ServerConfName = s.HTTPConfName; return s }(), // names equal
		func() Settings { s := base; s.NginxConf = "relative.conf"; return s }(),     // not absolute
		func() Settings { s := base; s.LogPath = ""; return s }(),                    // empty log
	}
	for i, s := range bad {
		if err := s.Validate(); err == nil {
			t.Errorf("bad[%d] %+v accepted", i, s)
		}
	}

	// NginxConf may be empty (use nginx default).
	ok := base
	ok.NginxConf = ""
	if err := ok.Validate(); err != nil {
		t.Errorf("empty nginx_conf must be allowed: %v", err)
	}
}

func TestSettingsConfPaths(t *testing.T) {
	s := DefaultSettings()
	if s.httpConfPath() != "/etc/nginx/waf/waf_http.conf" {
		t.Errorf("unexpected http path: %s", s.httpConfPath())
	}
	if s.serverConfPath() != "/etc/nginx/waf/waf_server.conf" {
		t.Errorf("unexpected server path: %s", s.serverConfPath())
	}
}
