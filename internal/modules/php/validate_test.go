package php

import "testing"

func TestValidVersion(t *testing.T) {
	ok := []string{"8.1", "7.4.33", "5", "8.2.10"}
	bad := []string{"", "8.x", "8.1; rm -rf /", "../etc", "8 1", "v8.1", "8.1\n", "8/1"}
	for _, v := range ok {
		if !ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if ValidVersion(v) {
			t.Errorf("ValidVersion(%q) = true, want false (injection must be rejected)", v)
		}
	}
}

func TestValidExtName(t *testing.T) {
	ok := []string{"redis", "opcache", "pdo_mysql", "Zend_OPcache"}
	bad := []string{"", "pdo-mysql", "redis;ls", "redis.so", "../x", "a b", "ext\n"}
	for _, v := range ok {
		if !ValidExtName(v) {
			t.Errorf("ValidExtName(%q) = false, want true", v)
		}
	}
	for _, v := range bad {
		if ValidExtName(v) {
			t.Errorf("ValidExtName(%q) = true, want false (injection must be rejected)", v)
		}
	}
}

func TestValidIniKeyWhitelist(t *testing.T) {
	if !ValidIniKey("memory_limit") {
		t.Error("memory_limit must be editable")
	}
	if !ValidIniKey("date.timezone") {
		t.Error("date.timezone must be editable")
	}
	// 危险/未列入白名单的 key 必须拒绝。
	for _, k := range []string{"disable_functions", "auto_prepend_file", "open_basedir", "", "memory_limit\n", "foo;bar"} {
		if ValidIniKey(k) {
			t.Errorf("ValidIniKey(%q) = true, want false", k)
		}
	}
}

func TestValidIniValueRejectsInjection(t *testing.T) {
	if !ValidIniValue("128M") {
		t.Error("128M must be a valid value")
	}
	if !ValidIniValue("Asia/Shanghai") {
		t.Error("timezone value must be valid")
	}
	// 截断/注入字符必须拒绝。
	for _, v := range []string{"128M\ndisable_functions = exec", "x\r", "v\x00", "1[section]"} {
		if ValidIniValue(v) {
			t.Errorf("ValidIniValue(%q) = true, want false", v)
		}
	}
}

func TestValidateIniChanges(t *testing.T) {
	if err := validateIniChanges(map[string]string{"memory_limit": "256M"}); err != nil {
		t.Errorf("valid change rejected: %v", err)
	}
	if err := validateIniChanges(map[string]string{"disable_functions": "exec"}); err == nil {
		t.Error("non-whitelisted key must be rejected")
	}
	if err := validateIniChanges(map[string]string{"memory_limit": "256M\ninjected = 1"}); err == nil {
		t.Error("value with newline must be rejected")
	}
}
