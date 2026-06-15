package files

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newShareStoreT(t *testing.T) *shareStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ss, err := newShareStore(st)
	if err != nil {
		t.Fatal(err)
	}
	return ss
}

func TestShareCreateGet(t *testing.T) {
	ss := newShareStoreT(t)
	tok, err := ss.create(Share{RelPath: "a/b", OwnerID: 7, AllowList: true, MaxDownloads: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) < 20 {
		t.Fatalf("token too short: %q", tok)
	}
	got, err := ss.get(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.RelPath != "a/b" || got.OwnerID != 7 || !got.AllowList || got.MaxDownloads != 3 {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestShareTokensUnique(t *testing.T) {
	ss := newShareStoreT(t)
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := ss.create(Share{RelPath: "x", OwnerID: 1})
		if err != nil {
			t.Fatal(err)
		}
		if seen[tok] {
			t.Fatalf("duplicate token %q", tok)
		}
		seen[tok] = true
	}
}

func TestShareRevokeOwnerOnly(t *testing.T) {
	ss := newShareStoreT(t)
	tok, _ := ss.create(Share{RelPath: "x", OwnerID: 1})

	// 非创建者、非 admin 不能撤销。
	ok, err := ss.revoke(tok, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("non-owner should not revoke")
	}
	if _, err := ss.get(tok); err != nil {
		t.Fatal("share should still exist")
	}

	// admin 可撤销任意分享。
	ok, err = ss.revoke(tok, 99, true)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("admin should revoke")
	}
	if _, err := ss.get(tok); err != ErrShareNotFound {
		t.Fatalf("revoked share should be gone, got %v", err)
	}
}

func TestIncDownloadIfAllowed(t *testing.T) {
	ss := newShareStoreT(t)
	tok, _ := ss.create(Share{RelPath: "x", OwnerID: 1, MaxDownloads: 1})
	if ok, _ := ss.incDownloadIfAllowed(tok); !ok {
		t.Fatal("1st should be allowed")
	}
	if ok, _ := ss.incDownloadIfAllowed(tok); ok {
		t.Fatal("2nd should be over limit")
	}
}
