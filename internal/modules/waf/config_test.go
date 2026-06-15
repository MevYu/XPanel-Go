package waf

import (
	"strings"
	"testing"
)

func TestGenerateConfigIPList(t *testing.T) {
	rs := RuleSet{
		IPRules: []IPRule{
			{Action: "deny", CIDR: "10.0.0.0/8", Enabled: true},
			{Action: "allow", CIDR: "1.2.3.4", Enabled: true},
			{Action: "deny", CIDR: "5.6.7.8", Enabled: false}, // disabled, must not appear
		},
		CC: DefaultCCConfig(),
	}
	cfg, err := GenerateConfig(rs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(cfg.Server, "allow 1.2.3.4;") {
		t.Errorf("missing allow directive:\n%s", cfg.Server)
	}
	if !strings.Contains(cfg.Server, "deny 10.0.0.0/8;") {
		t.Errorf("missing deny directive:\n%s", cfg.Server)
	}
	if strings.Contains(cfg.Server, "5.6.7.8") {
		t.Errorf("disabled rule leaked into config:\n%s", cfg.Server)
	}
	// allow must precede deny (whitelist-first ordering).
	if strings.Index(cfg.Server, "allow 1.2.3.4;") > strings.Index(cfg.Server, "deny 10.0.0.0/8;") {
		t.Errorf("allow must come before deny:\n%s", cfg.Server)
	}
}

func TestGenerateConfigDeterministic(t *testing.T) {
	rs := RuleSet{
		IPRules: []IPRule{
			{Action: "deny", CIDR: "9.9.9.9", Enabled: true},
			{Action: "deny", CIDR: "1.1.1.1", Enabled: true},
			{Action: "deny", CIDR: "5.5.5.5", Enabled: true},
		},
		CC: DefaultCCConfig(),
	}
	a, _ := GenerateConfig(rs)
	b, _ := GenerateConfig(rs)
	if a.Server != b.Server || a.HTTP != b.HTTP {
		t.Errorf("config generation must be deterministic")
	}
	// denies sorted: 1.1.1.1 < 5.5.5.5 < 9.9.9.9
	i1 := strings.Index(a.Server, "deny 1.1.1.1;")
	i5 := strings.Index(a.Server, "deny 5.5.5.5;")
	i9 := strings.Index(a.Server, "deny 9.9.9.9;")
	if !(i1 < i5 && i5 < i9) {
		t.Errorf("deny entries not sorted:\n%s", a.Server)
	}
}

func TestGenerateConfigMatchRules(t *testing.T) {
	rs := RuleSet{
		MatchRules: []MatchRule{
			{Target: "ua", Pattern: "sqlmap", Action: "block", Enabled: true},
			{Target: "uri", Pattern: `/wp-admin`, Action: "block", Enabled: true},
		},
		CC: DefaultCCConfig(),
	}
	cfg, err := GenerateConfig(rs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(cfg.HTTP, `map $http_user_agent $waf_block_ua`) {
		t.Errorf("missing UA map:\n%s", cfg.HTTP)
	}
	if !strings.Contains(cfg.HTTP, `"~*sqlmap" 1;`) {
		t.Errorf("missing UA block pattern:\n%s", cfg.HTTP)
	}
	if !strings.Contains(cfg.HTTP, `map $request_uri $waf_block_uri`) {
		t.Errorf("missing URI map:\n%s", cfg.HTTP)
	}
	if !strings.Contains(cfg.Server, "if ($waf_block_ua) { return 403; }") {
		t.Errorf("missing UA enforcement:\n%s", cfg.Server)
	}
	if !strings.Contains(cfg.Server, "if ($waf_block_uri) { return 403; }") {
		t.Errorf("missing URI enforcement:\n%s", cfg.Server)
	}
}

func TestGenerateConfigCC(t *testing.T) {
	rs := RuleSet{CC: CCConfig{Enabled: true, RatePerSec: 5, Burst: 10, ConnPerIP: 8, ZoneSizeMB: 16}}
	cfg, err := GenerateConfig(rs)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !strings.Contains(cfg.HTTP, "limit_req_zone $binary_remote_addr zone=waf_req:16m rate=5r/s;") {
		t.Errorf("missing limit_req_zone:\n%s", cfg.HTTP)
	}
	if !strings.Contains(cfg.HTTP, "limit_conn_zone $binary_remote_addr zone=waf_conn:16m;") {
		t.Errorf("missing limit_conn_zone:\n%s", cfg.HTTP)
	}
	if !strings.Contains(cfg.Server, "limit_req zone=waf_req burst=10 nodelay;") {
		t.Errorf("missing limit_req:\n%s", cfg.Server)
	}
	if !strings.Contains(cfg.Server, "limit_conn waf_conn 8;") {
		t.Errorf("missing limit_conn:\n%s", cfg.Server)
	}
}

func TestGenerateConfigCCDisabledOmitsLimits(t *testing.T) {
	rs := RuleSet{CC: CCConfig{Enabled: false}}
	cfg, _ := GenerateConfig(rs)
	if strings.Contains(cfg.HTTP, "limit_req_zone") || strings.Contains(cfg.Server, "limit_req ") {
		t.Errorf("disabled CC must not emit limit directives")
	}
}

// TestGenerateConfigRejectsInjection 是核心安全测试:即便恶意规则绕过上游 Validate 进了
// RuleSet,GenerateConfig 必须二次校验并拒绝,绝不输出被污染的配置。
func TestGenerateConfigRejectsInjection(t *testing.T) {
	cases := []RuleSet{
		{IPRules: []IPRule{{Action: "deny", CIDR: "1.2.3.4; return 444", Enabled: true}}, CC: DefaultCCConfig()},
		{MatchRules: []MatchRule{{Target: "uri", Pattern: `x"; } location / { deny all`, Action: "block", Enabled: true}}, CC: DefaultCCConfig()},
		{MatchRules: []MatchRule{{Target: "ua", Pattern: "$request_uri", Action: "block", Enabled: true}}, CC: DefaultCCConfig()},
		{CC: CCConfig{Enabled: true, RatePerSec: 0, ZoneSizeMB: 10}},
	}
	for i, rs := range cases {
		cfg, err := GenerateConfig(rs)
		if err == nil {
			t.Errorf("case %d: malicious ruleset accepted, got config:\n%s", i, cfg.Server+cfg.HTTP)
		}
	}
}
