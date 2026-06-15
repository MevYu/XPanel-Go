package ssl

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *sslStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	ss, err := newSSLStore(st)
	if err != nil {
		t.Fatalf("new ssl store: %v", err)
	}
	return ss
}

func TestStoreCRUD(t *testing.T) {
	ss := newTestStore(t)
	uid := int64(3)
	id, err := ss.create(Cert{
		Domains: "example.com,www.example.com", Issuer: "letsencrypt",
		Challenge: "webroot", CertPath: "/c/fullchain.pem", KeyPath: "/c/privkey.pem",
		NotAfter: 1000, AutoRenew: true, CreatedBy: &uid,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	c, err := ss.get(id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if c.Domains != "example.com,www.example.com" || !c.AutoRenew || c.NotAfter != 1000 {
		t.Errorf("unexpected cert: %+v", c)
	}
	if c.CreatedBy == nil || *c.CreatedBy != 3 {
		t.Errorf("created_by not persisted: %+v", c.CreatedBy)
	}

	list, err := ss.list()
	if err != nil || len(list) != 1 {
		t.Fatalf("list = %d, err %v", len(list), err)
	}

	if err := ss.setAutoRenew(id, false); err != nil {
		t.Fatalf("setAutoRenew: %v", err)
	}
	c, _ = ss.get(id)
	if c.AutoRenew {
		t.Error("auto-renew should be off")
	}

	if err := ss.markRenewed(id, 5000); err != nil {
		t.Fatalf("markRenewed: %v", err)
	}
	c, _ = ss.get(id)
	if c.NotAfter != 5000 || c.LastRenewAt == nil {
		t.Errorf("renew not recorded: %+v", c)
	}

	if err := ss.delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := ss.get(id); err == nil {
		t.Error("get after delete should error")
	}
}

func TestStoreAutoRenewable(t *testing.T) {
	ss := newTestStore(t)
	// 到期 100,开启自动续期 -> due
	due, _ := ss.create(Cert{Domains: "a.com", CertPath: "/a", KeyPath: "/ak", NotAfter: 100, AutoRenew: true})
	// 到期 9999,远未到期 -> not due
	ss.create(Cert{Domains: "b.com", CertPath: "/b", KeyPath: "/bk", NotAfter: 9999, AutoRenew: true})
	// 到期 100,但关闭自动续期 -> not due
	ss.create(Cert{Domains: "c.com", CertPath: "/c", KeyPath: "/ck", NotAfter: 100, AutoRenew: false})
	// 到期未知(0) -> not due
	ss.create(Cert{Domains: "d.com", CertPath: "/d", KeyPath: "/dk", NotAfter: 0, AutoRenew: true})

	got, err := ss.autoRenewable(500)
	if err != nil {
		t.Fatalf("autoRenewable: %v", err)
	}
	if len(got) != 1 || got[0].ID != due {
		t.Fatalf("want only cert %d due, got %+v", due, got)
	}
}

func TestStoreSettings(t *testing.T) {
	ss := newTestStore(t)
	v, err := ss.getSetting(keyCertDir, defaultCertDir)
	if err != nil || v != defaultCertDir {
		t.Fatalf("default fallback failed: %q %v", v, err)
	}
	if err := ss.setSetting(keyCertDir, "/custom/cert"); err != nil {
		t.Fatalf("setSetting: %v", err)
	}
	v, _ = ss.getSetting(keyCertDir, defaultCertDir)
	if v != "/custom/cert" {
		t.Errorf("got %q, want /custom/cert", v)
	}
	// upsert 覆盖
	ss.setSetting(keyCertDir, "/again")
	v, _ = ss.getSetting(keyCertDir, defaultCertDir)
	if v != "/again" {
		t.Errorf("upsert failed, got %q", v)
	}
}
