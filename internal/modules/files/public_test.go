package files

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MevYu/XPanel-Go/internal/auth"
)

// makeShare 直接在 store 里建一条分享,返回 token。
func makeShare(t *testing.T, m *Module, sh Share) string {
	t.Helper()
	tok, err := m.shares.create(sh)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func getPublic(m *Module, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", path, nil)
	m.PublicRoutes().ServeHTTP(rec, req)
	return rec
}

func TestPublicSingleFileDownload(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "doc.txt"), []byte("public"), 0o644); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "doc.txt", OwnerID: 1})
	rec := getPublic(m, "/"+tok)
	if rec.Code != http.StatusOK || rec.Body.String() != "public" {
		t.Fatalf("got %d %q", rec.Code, rec.Body)
	}
}

func TestPublicDirListingDisabledByDefault(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.MkdirAll(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "d", OwnerID: 1, AllowList: false})
	rec := getPublic(m, "/"+tok)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("dir listing should be 403 when disabled, got %d", rec.Code)
	}
}

func TestPublicDirListingAllowed(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.MkdirAll(filepath.Join(root, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "d", "inside.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "d", OwnerID: 1, AllowList: true})
	rec := getPublic(m, "/"+tok)
	if rec.Code != http.StatusOK {
		t.Fatalf("listing want 200, got %d", rec.Code)
	}
	if !contains(rec.Body.String(), "inside.txt") {
		t.Fatalf("listing missing entry: %s", rec.Body)
	}
}

// 关键:公开端点的子路径不能逃出分享子树(独立于面板根)。
func TestPublicSubpathTraversalRejected(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	// 面板根内有一个 secret,在分享子树之外。
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "shared", OwnerID: 1, AllowList: true})

	// 试图用 ../ 跳到 shared 之外去读 secret.txt。
	rec := getPublic(m, "/"+tok+"/../secret.txt")
	if rec.Code == http.StatusOK && contains(rec.Body.String(), "S") {
		t.Fatalf("public subpath escaped share root and read secret")
	}
}

func TestPublicSymlinkEscapeRejected(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "shared"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "shared", "link")); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "shared", OwnerID: 1, AllowList: true})
	rec := getPublic(m, "/"+tok+"/link/secret")
	if rec.Code == http.StatusOK {
		t.Fatalf("public symlink escape succeeded, got %d body=%q", rec.Code, rec.Body)
	}
}

func TestPublicExpired(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "f", OwnerID: 1, ExpiresAt: nowUnix() - 10})
	rec := getPublic(m, "/"+tok)
	if rec.Code != http.StatusGone {
		t.Fatalf("expired share want 410, got %d", rec.Code)
	}
}

func TestPublicPasswordRequired(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 用模块创建带密码的分享走真实 hash。
	req := shareCreateReq{Path: "f", Password: "hunter2"}
	tok := createViaAPI(t, m, req)

	// 无密码 → 401
	if rec := getPublic(m, "/"+tok); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-password want 401, got %d", rec.Code)
	}
	// 错密码 → 401
	if rec := getPublic(m, "/"+tok+"?pw=wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad-password want 401, got %d", rec.Code)
	}
	// 对密码 → 200
	if rec := getPublic(m, "/"+tok+"?pw=hunter2"); rec.Code != http.StatusOK || rec.Body.String() != "secret" {
		t.Fatalf("good-password want 200 secret, got %d %q", rec.Code, rec.Body)
	}
}

func TestPublicDownloadLimit(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	tok := makeShare(t, m, Share{RelPath: "f", OwnerID: 1, MaxDownloads: 2})
	if rec := getPublic(m, "/"+tok); rec.Code != http.StatusOK {
		t.Fatalf("1st download want 200, got %d", rec.Code)
	}
	if rec := getPublic(m, "/"+tok); rec.Code != http.StatusOK {
		t.Fatalf("2nd download want 200, got %d", rec.Code)
	}
	if rec := getPublic(m, "/"+tok); rec.Code != http.StatusGone {
		t.Fatalf("3rd download over-limit want 410, got %d", rec.Code)
	}
}

func TestPublicUnknownToken404(t *testing.T) {
	m, _, _ := newModule(t, "operator")
	if rec := getPublic(m, "/doesnotexist"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown token want 404, got %d", rec.Code)
	}
}

// 关键:公开端点不暴露任何写能力 / 面板路由。PublicRoutes 只挂 GET,POST 必须不可达。
func TestPublicRejectsWriteMethods(t *testing.T) {
	m, _, _ := newModule(t, "operator")
	for _, method := range []string{"POST", "PUT", "DELETE", "PATCH"} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(method, "/sometoken", nil)
		m.PublicRoutes().ServeHTTP(rec, req)
		if rec.Code == http.StatusOK {
			t.Fatalf("%s on public route should not be OK", method)
		}
	}
}

// 关键:公开端点不消费面板 JWT —— 带 Bearer 也不能绕过 token/路径限定。
func TestPublicIgnoresPanelBearer(t *testing.T) {
	m, root, _ := newModule(t, "operator")
	if err := os.WriteFile(filepath.Join(root, "secret.txt"), []byte("S"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/secret.txt", nil) // 把文件名当 token
	req.Header.Set("Authorization", "Bearer anything")
	m.PublicRoutes().ServeHTTP(rec, req)
	// "secret.txt" 不是有效 token → 404,Bearer 头被完全忽略。
	if rec.Code != http.StatusNotFound {
		t.Fatalf("panel bearer must not grant access, got %d", rec.Code)
	}
}

func createViaAPI(t *testing.T, m *Module, req shareCreateReq) string {
	t.Helper()
	h, err := auth.HashPassword(req.Password)
	if err != nil {
		t.Fatal(err)
	}
	sh := Share{
		RelPath: normalizeRel(req.Path), OwnerID: 1, PassHash: h,
		AllowList: req.AllowList, MaxDownloads: req.MaxDownloads,
	}
	return makeShare(t, m, sh)
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
