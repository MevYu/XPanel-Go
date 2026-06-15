package php

import (
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
