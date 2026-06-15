package backup

import (
	"testing"

	"github.com/MevYu/XPanel-Go/internal/store"
)

func newTestStore(t *testing.T) *backupStore {
	t.Helper()
	st, err := store.Open(":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	cryp, err := newCryptor("secret")
	if err != nil {
		t.Fatal(err)
	}
	bs, err := newBackupStore(st, cryp)
	if err != nil {
		t.Fatal(err)
	}
	return bs
}

func TestSettingsDefaultsAndOverride(t *testing.T) {
	bs := newTestStore(t)
	def, err := bs.settings()
	if err != nil {
		t.Fatal(err)
	}
	if def.BackupDir != defaultBackupDir {
		t.Errorf("default backup dir = %q, want %q", def.BackupDir, defaultBackupDir)
	}
	if def.MysqlDump != "mysqldump" || def.PgDump != "pg_dump" {
		t.Errorf("default dump cmds wrong: %+v", def)
	}
	if err := bs.saveSettings(Settings{BackupDir: "/data/backup"}); err != nil {
		t.Fatal(err)
	}
	got, _ := bs.settings()
	if got.BackupDir != "/data/backup" {
		t.Errorf("override backup dir = %q", got.BackupDir)
	}
	// 未覆盖字段回落默认
	if got.MysqlDump != "mysqldump" {
		t.Errorf("unset mysqldump should default, got %q", got.MysqlDump)
	}
}

func TestRemoteSecretEncryptedAtRest(t *testing.T) {
	bs := newTestStore(t)
	r, err := bs.addRemote(Remote{Name: "s3", Type: "s3", Bucket: "b", AccessKey: "AK", Secret: "topsecret"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Secret != "" {
		t.Error("addRemote must not echo secret back")
	}
	if !r.SecretSet {
		t.Error("secret_set should be true")
	}
	// 落库密文不应等于明文
	var enc string
	if err := bs.db.QueryRow(`SELECT secret_enc FROM backup_remotes WHERE id=?`, r.ID).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if enc == "" || enc == "topsecret" {
		t.Errorf("secret not encrypted at rest: %q", enc)
	}
	// getRemote 解密回明文(内部用)
	got, err := bs.getRemote(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "topsecret" {
		t.Errorf("getRemote secret = %q, want topsecret", got.Secret)
	}
	// listRemotes 屏蔽 secret
	list, _ := bs.listRemotes()
	if len(list) != 1 || list[0].Secret != "" {
		t.Errorf("listRemotes leaks secret: %+v", list)
	}
	if !list[0].SecretSet {
		t.Error("listRemotes should report secret_set")
	}
}

func TestRemoteDelete(t *testing.T) {
	bs := newTestStore(t)
	r, _ := bs.addRemote(Remote{Name: "r", Type: "s3"})
	if err := bs.deleteRemote(r.ID); err != nil {
		t.Fatal(err)
	}
	list, _ := bs.listRemotes()
	if len(list) != 0 {
		t.Errorf("remote not deleted: %+v", list)
	}
}

func TestJobCRUD(t *testing.T) {
	bs := newTestStore(t)
	j, err := bs.addJob(Job{Name: "nightly", TargetKind: "path", Target: "/www/site", Keep: 3, Frequency: "daily"})
	if err != nil {
		t.Fatal(err)
	}
	if j.ID == 0 {
		t.Fatal("job id not set")
	}
	got, err := bs.getJob(j.ID)
	if err != nil || got.Keep != 3 || got.Name != "nightly" {
		t.Errorf("getJob = %+v err %v", got, err)
	}
	list, _ := bs.listJobs()
	if len(list) != 1 {
		t.Fatalf("listJobs len = %d", len(list))
	}
	if err := bs.deleteJob(j.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := bs.listJobs(); len(list) != 0 {
		t.Error("job not deleted")
	}
}

func TestRecordsAndRetention(t *testing.T) {
	bs := newTestStore(t)
	jid := int64(7)
	// 5 条本地备份记录(顺序写入,created_at 单调)
	for i := 0; i < 5; i++ {
		if _, err := bs.addRecord(Record{JobID: &jid, TargetKind: "path", Target: "/x", Filename: "f", Location: "local", Size: 100}); err != nil {
			t.Fatal(err)
		}
	}
	// 一条远端记录不应参与本地保留策略
	rid := int64(1)
	bs.addRecord(Record{JobID: &jid, Target: "/x", Filename: "f", Location: "remote", RemoteID: &rid})

	stale, err := bs.staleLocalRecords(jid, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(stale) != 3 {
		t.Fatalf("keep=2 over 5 local should yield 3 stale, got %d", len(stale))
	}
	// stale 应为最旧的三条(id 1,2,3,升序)
	if stale[0].ID > stale[len(stale)-1].ID {
		t.Error("stale should be oldest-first ascending")
	}
	for _, r := range stale {
		if r.Location != "local" {
			t.Errorf("stale must be local only, got %q", r.Location)
		}
	}

	// keep=0 不清理
	if s, _ := bs.staleLocalRecords(jid, 0); s != nil {
		t.Error("keep=0 should not prune")
	}
	// keep >= count 不清理
	if s, _ := bs.staleLocalRecords(jid, 10); s != nil {
		t.Error("keep >= count should not prune")
	}
}

func TestListRecordsFilterByJob(t *testing.T) {
	bs := newTestStore(t)
	a, b := int64(1), int64(2)
	bs.addRecord(Record{JobID: &a, Target: "/a", Filename: "f", Location: "local"})
	bs.addRecord(Record{JobID: &b, Target: "/b", Filename: "f", Location: "local"})
	all, _ := bs.listRecords(nil)
	if len(all) != 2 {
		t.Errorf("all records = %d", len(all))
	}
	only, _ := bs.listRecords(&a)
	if len(only) != 1 || *only[0].JobID != a {
		t.Errorf("filtered records = %+v", only)
	}
}
