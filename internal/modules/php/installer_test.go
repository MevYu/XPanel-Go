package php

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// okInstaller 是成功安装的 mock,记录请求的版本。
type okInstaller struct{ installed []string }

func (i *okInstaller) Available() error { return nil }
func (i *okInstaller) Install(v string) (string, error) {
	i.installed = append(i.installed, v)
	return "installed " + v, nil
}

// failInstaller 模拟失败安装,输出含内部路径/状态(绝不能回传客户端)。
type failInstaller struct{ output string }

func (failInstaller) Available() error { return nil }
func (i failInstaller) Install(string) (string, error) {
	return i.output, errors.New("apt failed")
}

func TestUnavailableInstaller(t *testing.T) {
	inst := NewUnavailableInstaller()
	if inst.Available() == nil {
		t.Error("default installer must report unavailable")
	}
	if _, err := inst.Install("8.3"); err == nil {
		t.Error("default installer Install must error")
	}
}

func TestInstallWithBackendSucceeds(t *testing.T) {
	inst := &okInstaller{}
	_, audited, r := newTestModule(t, "admin", &mockRunner{}, inst)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/install", strings.NewReader(`{"version":"8.3"}`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("install with backend = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(inst.installed) != 1 || inst.installed[0] != "8.3" {
		t.Errorf("installer got %v, want [8.3]", inst.installed)
	}
	if *audited != 1 {
		t.Errorf("must audit once, got %d", *audited)
	}
}

// 安装失败时,响应体绝不能含命令原始输出(路径/内部状态)。
func TestInstallFailureBodyOmitsRawOutput(t *testing.T) {
	const secret = "/opt/secret/path apt: E: could not configure"
	_, _, r := newTestModule(t, "admin", &mockRunner{}, failInstaller{output: secret})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/install", strings.NewReader(`{"version":"8.3"}`))
	req.Header.Set("X-Confirm-Danger", "1")
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed install = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), secret) || strings.Contains(rec.Body.String(), "/opt/secret") {
		t.Errorf("response leaked raw install output: %q", rec.Body.String())
	}
}

// 缺 X-Confirm-Danger 时危险操作被拒(428),不触达后端、不审计。
func TestInstallRequiresConfirm(t *testing.T) {
	inst := &okInstaller{}
	_, audited, r := newTestModule(t, "admin", &mockRunner{}, inst)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/install", strings.NewReader(`{"version":"8.3"}`))
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("install without confirm = %d, want 428", rec.Code)
	}
	if len(inst.installed) != 0 || *audited != 0 {
		t.Errorf("unconfirmed install must not act or audit")
	}
}

// php.ini/扩展/fpm 三个危险操作缺确认头一律 428。
func TestDangerOpsRequireConfirm(t *testing.T) {
	cases := []struct{ method, path, body string }{
		{"PUT", "/versions/8.1/ini", `{"memory_limit":"256M"}`},
		{"POST", "/versions/8.1/extensions/redis/enable", ""},
		{"POST", "/versions/8.1/fpm/restart", ""},
	}
	for _, c := range cases {
		m, audited, r := newTestModule(t, "admin", &mockRunner{}, nil)
		setupInstall(t, m)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusPreconditionRequired {
			t.Errorf("%s %s without confirm = %d, want 428", c.method, c.path, rec.Code)
		}
		if *audited != 0 {
			t.Errorf("%s %s unconfirmed must not audit", c.method, c.path)
		}
	}
}
