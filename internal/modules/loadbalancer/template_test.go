package loadbalancer

import (
	"strings"
	"testing"
)

func TestRenderGroupShape(t *testing.T) {
	g, err := buildGroup(createRequest{
		Name:       "api",
		Algo:       "least_conn",
		Listen:     8443,
		ServerName: "api.example.com",
		Backends: []backendRequest{
			{Host: "192.168.1.10", Port: 3000, Weight: 5, MaxFails: 2, FailTimeout: "10s"},
			{Host: "backend.internal", Port: 3000},
		},
	})
	if err != nil {
		t.Fatalf("buildGroup: %v", err)
	}
	cfg, err := renderGroup(g)
	if err != nil {
		t.Fatalf("renderGroup: %v", err)
	}
	for _, want := range []string{
		"upstream xpanel_lb_api {",
		"least_conn;",
		"server 192.168.1.10:3000 weight=5 max_fails=2 fail_timeout=10s;",
		"server backend.internal:3000 weight=1;",
		"listen 8443;",
		"server_name api.example.com;",
		"proxy_pass http://xpanel_lb_api;",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("rendered config missing %q:\n%s", want, cfg)
		}
	}
}

// assertNoInjection 是绕过校验层时的最后防线:控制字符必须被拒。
func TestAssertNoInjectionCatchesControlChars(t *testing.T) {
	g := Group{
		Name:       "x",
		Algo:       "round-robin",
		Listen:     80,
		ServerName: "ok.com",
		Backends:   []Backend{{Host: "1.2.3.4\nserver evil;", Port: 80, Weight: 1}},
	}
	if _, err := renderGroup(g); err == nil {
		t.Fatal("renderGroup must reject control characters in backend host")
	}
}

func TestValidators(t *testing.T) {
	if validGroupName("bad name") || validGroupName("../x") || validGroupName("") {
		t.Error("validGroupName accepted invalid input")
	}
	if !validGroupName("web-1.app") {
		t.Error("validGroupName rejected valid input")
	}
	if validBackendHost("1.2.3.4:80") || validBackendHost("http://x") || validBackendHost("a b") {
		t.Error("validBackendHost accepted invalid input")
	}
	if !validBackendHost("10.0.0.1") || !validBackendHost("svc.internal") {
		t.Error("validBackendHost rejected valid input")
	}
	if validAlgo("random") || !validAlgo("ip_hash") {
		t.Error("validAlgo wrong")
	}
	if validFailTimeout("30; x") || validFailTimeout("") || !validFailTimeout("30s") || !validFailTimeout("5m") {
		t.Error("validFailTimeout wrong")
	}
	if validWeight(0) || validWeight(101) || !validWeight(1) {
		t.Error("validWeight wrong")
	}
	if validPort(0) || validPort(70000) || !validPort(8080) {
		t.Error("validPort wrong")
	}
}
