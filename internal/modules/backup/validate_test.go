package backup

import "testing"

func TestValidToolPath(t *testing.T) {
	ok := []string{"", "mysqldump", "pg_dump", "/usr/bin/mysqldump", "/opt/db/bin/pg_dump"}
	for _, p := range ok {
		if !validToolPath(p) {
			t.Errorf("validToolPath(%q) = false, want true", p)
		}
	}
	bad := []string{
		"mysqldump; rm -rf /",
		"bin/mysqldump",        // 相对路径带分隔符,不允许
		"../../usr/bin/evil",   // 相对穿越
		"/usr/bin/../bin/x/..", // 非 Clean 绝对路径
		"mysqldump\nfoo",       // 换行注入
		"/usr/bin/dump\x00",    // NUL
		"dump$(whoami)",        // shell 元字符
	}
	for _, p := range bad {
		if validToolPath(p) {
			t.Errorf("validToolPath(%q) = true, want false", p)
		}
	}
}

func TestValidEndpoint(t *testing.T) {
	ok := []string{"", "https://s3.example.com", "http://192.168.1.10:9000", "https://oss-cn-hangzhou.aliyuncs.com"}
	for _, e := range ok {
		if !validEndpoint(e) {
			t.Errorf("validEndpoint(%q) = false, want true", e)
		}
	}
	bad := []string{"s3.example.com", "ftp://x", "javascript:alert(1)", "://nohost", "https://"}
	for _, e := range bad {
		if validEndpoint(e) {
			t.Errorf("validEndpoint(%q) = true, want false", e)
		}
	}
}

func TestValidRegion(t *testing.T) {
	ok := []string{"", "us-east-1", "cn-hangzhou", "eu_west_2"}
	for _, rg := range ok {
		if !validRegion(rg) {
			t.Errorf("validRegion(%q) = false, want true", rg)
		}
	}
	bad := []string{"us east", "rg;rm", "rg/../x", "rg\n"}
	for _, rg := range bad {
		if validRegion(rg) {
			t.Errorf("validRegion(%q) = true, want false", rg)
		}
	}
}
