package sites

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRestoreBackupDangerGuards(t *testing.T) {
	// 以 operator 建站 + 备份,再用不同角色模块尝试 restore(共享同一 DB 不便,故每用例独立模块)。
	m, _ := newBackupModule(t, "operator")
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)

	// 无确认头 → 428
	rec = do(m, "POST", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID)+"/restore", nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("restore without confirm should 428, got %d", rec.Code)
	}
	// operator + 确认头 → 403
	rec = do(m, "POST", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID)+"/restore", nil, confirm())
	if rec.Code != http.StatusForbidden {
		t.Fatalf("operator restore should 403, got %d", rec.Code)
	}
}

func TestRestoreBackupAdminConfirmed(t *testing.T) {
	m, arc := newBackupModule(t, "admin")
	id := seedSite(t, m)
	site := getSite(t, m, id)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)

	rec = do(m, "POST", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID)+"/restore", nil, confirm())
	if rec.Code != http.StatusOK {
		t.Fatalf("admin restore should 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(arc.unpacks) != 1 || arc.unpacks[0].dest != site.RootDir {
		t.Errorf("Unpack should target RootDir %q, got %+v", site.RootDir, arc.unpacks)
	}
}

func TestRestoreBackupUnpackError(t *testing.T) {
	m, arc := newBackupModule(t, "admin")
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)
	arc.unpackErr = &testError{"zip-slip"}
	rec = do(m, "POST", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID)+"/restore", nil, confirm())
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unpack error should 400, got %d", rec.Code)
	}
}

func TestDeleteBackupDangerGuards(t *testing.T) {
	m, _ := newBackupModule(t, "operator")
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)
	rec = do(m, "DELETE", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID), nil, nil)
	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("delete without confirm should 428, got %d", rec.Code)
	}
}

func TestDeleteBackupAdminConfirmed(t *testing.T) {
	m, arc := newBackupModule(t, "admin")
	id := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)

	rec = do(m, "DELETE", "/sites/"+itoa(id)+"/backups/"+itoa(b.ID), nil, confirm())
	if rec.Code != http.StatusNoContent {
		t.Fatalf("admin delete should 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	if len(arc.removes) != 1 {
		t.Error("delete must remove archive file")
	}
	list, _ := m.ss.listBackups(id)
	if len(list) != 0 {
		t.Errorf("metadata not deleted, got %d", len(list))
	}
}

// 跨站点访问他人备份必须 404(归属校验)。
func TestBackupCrossSiteForbidden(t *testing.T) {
	m, _ := newBackupModule(t, "admin")
	id1 := seedSite(t, m)
	rec := do(m, "POST", "/sites/"+itoa(id1)+"/backups", nil, nil)
	var b Backup
	json.Unmarshal(rec.Body.Bytes(), &b)
	// 另建一个站点
	rec = do(m, "POST", "/sites", createRequest{Domains: []string{"other.example.com"}, Kind: "static"}, nil)
	var other Site
	json.Unmarshal(rec.Body.Bytes(), &other)

	// 用 site2 路径访问 site1 的备份 → 404
	for _, tc := range []struct {
		method, path string
		hdr          map[string]string
	}{
		{"GET", "/sites/" + itoa(other.ID) + "/backups/" + itoa(b.ID) + "/download", nil},
		{"POST", "/sites/" + itoa(other.ID) + "/backups/" + itoa(b.ID) + "/restore", confirm()},
		{"DELETE", "/sites/" + itoa(other.ID) + "/backups/" + itoa(b.ID), confirm()},
	} {
		rec := do(m, tc.method, tc.path, nil, tc.hdr)
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s cross-site = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
}
