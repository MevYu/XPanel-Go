package system

import "testing"

func TestValidUnitName(t *testing.T) {
	valid := []string{"nginx", "nginx.service", "ssh", "my-app_1.service"}
	for _, n := range valid {
		if !ValidUnitName(n) {
			t.Errorf("%q should be valid", n)
		}
	}
	invalid := []string{"", "nginx;rm -rf", "a b", "../etc", "x&y", "$(whoami)", "a|b"}
	for _, n := range invalid {
		if ValidUnitName(n) {
			t.Errorf("%q should be invalid (injection risk)", n)
		}
	}
}

func TestServiceActionRejectsBadUnit(t *testing.T) {
	if _, err := ServiceAction("restart", "nginx; rm -rf /"); err == nil {
		t.Error("ServiceAction must reject injection-laden unit name")
	}
}

func TestServiceActionRejectsBadVerb(t *testing.T) {
	if _, err := ServiceAction("destroy", "nginx"); err == nil {
		t.Error("only whitelisted verbs allowed")
	}
}
