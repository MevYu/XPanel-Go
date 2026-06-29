package system

import (
	"regexp"
	"strings"
	"testing"
)

func TestValidCronExpr(t *testing.T) {
	valid := []string{
		"* * * * *",
		"0 3 * * *",
		"*/5 * * * *",
		"0 0 1,15 * *",
		"0 9 * * MON-FRI",
		"15 14 1 * *",
	}
	for _, e := range valid {
		if !ValidCronExpr(e) {
			t.Errorf("%q should be valid", e)
		}
	}
	invalid := []string{
		"",
		"* * * *",             // 只有 4 段
		"* * * * * *",         // 6 段
		"0 3 * * *; rm -rf /", // 注入
		"0 3 * *\n* echo",     // 换行
		"0 3 * * $(whoami)",   // 命令替换
	}
	for _, e := range invalid {
		if ValidCronExpr(e) {
			t.Errorf("%q should be invalid", e)
		}
	}
}

func TestValidCronCommand(t *testing.T) {
	valid := []string{
		"/usr/bin/backup.sh",
		"echo hello && date",
		"python3 /opt/app/job.py --flag",
	}
	for _, c := range valid {
		if !ValidCronCommand(c) {
			t.Errorf("%q should be valid", c)
		}
	}
	invalid := []string{
		"",
		"  ",
		"echo a\nrm -rf /", // 换行 -> 多写一行 crontab
		"echo a\r* * *",    // 回车
		"mail %stdin",      // % 在 crontab 是 stdin 分隔符
	}
	for _, c := range invalid {
		if ValidCronCommand(c) {
			t.Errorf("%q should be invalid (crontab injection risk)", c)
		}
	}
}

func TestRenderManagedBlockHasMarkers(t *testing.T) {
	const key = "abc123"
	out := RenderManagedBlock(key, []CronJobLine{
		{ID: 1, Expr: "0 3 * * *", Command: "/bin/backup.sh", Comment: "nightly backup"},
	})
	if !strings.Contains(out, cronBeginMarker(key)) || !strings.Contains(out, cronEndMarker(key)) {
		t.Fatal("managed block must contain keyed begin/end markers")
	}
	if !strings.Contains(out, "0 3 * * * /bin/backup.sh") {
		t.Errorf("rendered block missing job line:\n%s", out)
	}
	if !strings.Contains(out, "# nightly backup") {
		t.Errorf("rendered block missing comment:\n%s", out)
	}
}

func TestRenderManagedBlockSanitizesComment(t *testing.T) {
	out := RenderManagedBlock("abc123", []CronJobLine{
		{ID: 1, Expr: "* * * * *", Command: "true", Comment: "evil\n0 0 * * * rm -rf /"},
	})
	// 备注里的换行被替换为空格,不得新增一行 cron。
	for _, ln := range strings.Split(out, "\n") {
		if strings.Contains(ln, "rm -rf") && !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			t.Errorf("comment newline injected a real cron line: %q", ln)
		}
	}
}

func TestMergeManagedBlockReplacesOld(t *testing.T) {
	const key = "abc123"
	existing := "MAILTO=root\n0 1 * * * /user/own.sh\n" +
		cronBeginMarker(key) + "\n0 9 * * * /old.sh\n" + cronEndMarker(key) + "\n"
	managed := RenderManagedBlock(key, []CronJobLine{
		{ID: 2, Expr: "0 10 * * *", Command: "/new.sh"},
	})
	merged := MergeManagedBlock(existing, managed, key)

	if strings.Contains(merged, "/old.sh") {
		t.Error("old managed block must be replaced")
	}
	if !strings.Contains(merged, "/new.sh") {
		t.Error("new managed block must be present")
	}
	if !strings.Contains(merged, "MAILTO=root") || !strings.Contains(merged, "/user/own.sh") {
		t.Error("user lines outside managed block must be preserved")
	}
	// 托管标记只应出现一次。
	if strings.Count(merged, cronBeginMarker(key)) != 1 {
		t.Errorf("expected exactly one managed block, got:\n%s", merged)
	}
}

func TestMergeManagedBlockAppendsWhenNone(t *testing.T) {
	const key = "abc123"
	existing := "0 1 * * * /user/own.sh\n"
	managed := RenderManagedBlock(key, nil)
	merged := MergeManagedBlock(existing, managed, key)
	if !strings.Contains(merged, "/user/own.sh") {
		t.Error("user line lost")
	}
	if strings.Count(merged, cronBeginMarker(key)) != 1 {
		t.Error("managed block should be appended exactly once")
	}
}

// TestMultiInstanceConflictBug 复现多实例冲突:两个实例(不同 key)各写自己的托管区,
// 第二个实例 sync 不得删掉第一个实例的块。当前固定标记下此测试应失败(红)。
func TestMultiInstanceConflictBug(t *testing.T) {
	const keyA, keyB = "aaaa1111", "bbbb2222"
	user := "MAILTO=root\n5 5 * * * /user/own.sh\n"

	ctA := MergeManagedBlock(user,
		RenderManagedBlock(keyA, []CronJobLine{{ID: 1, Expr: "0 3 * * *", Command: "/a/job.sh"}}), keyA)
	ctB := MergeManagedBlock(ctA,
		RenderManagedBlock(keyB, []CronJobLine{{ID: 2, Expr: "0 4 * * *", Command: "/b/job.sh"}}), keyB)

	if !strings.Contains(ctB, "/a/job.sh") {
		t.Fatalf("instance A's job was clobbered by instance B's sync:\n%s", ctB)
	}
	if !strings.Contains(ctB, "/b/job.sh") {
		t.Fatalf("instance B's job missing:\n%s", ctB)
	}
	if !strings.Contains(ctB, "/user/own.sh") {
		t.Fatalf("user manual line lost:\n%s", ctB)
	}
}

// TestMergeManagedBlockDisableOnlyRemovesOwn:实例 B 清空自己的任务(禁用)后,
// sync 只删 B 的任务,A 的块与用户手工行原样保留。
func TestMergeManagedBlockDisableOnlyRemovesOwn(t *testing.T) {
	const keyA, keyB = "aaaa1111", "bbbb2222"
	user := "MAILTO=root\n5 5 * * * /user/own.sh\n"
	ct := MergeManagedBlock(user,
		RenderManagedBlock(keyA, []CronJobLine{{Expr: "0 3 * * *", Command: "/a/job.sh"}}), keyA)
	ct = MergeManagedBlock(ct,
		RenderManagedBlock(keyB, []CronJobLine{{Expr: "0 4 * * *", Command: "/b/job.sh"}}), keyB)

	// B 禁用:无启用任务 -> 空块。
	ct = MergeManagedBlock(ct, RenderManagedBlock(keyB, nil), keyB)

	if strings.Contains(ct, "/b/job.sh") {
		t.Errorf("disabled instance B's job must be gone:\n%s", ct)
	}
	if !strings.Contains(ct, "/a/job.sh") {
		t.Errorf("instance A's job must be preserved when B disables:\n%s", ct)
	}
	if !strings.Contains(ct, "/user/own.sh") {
		t.Errorf("user manual line must be preserved:\n%s", ct)
	}
	if strings.Count(ct, cronBeginMarker(keyA)) != 1 {
		t.Errorf("instance A's block must remain exactly once:\n%s", ct)
	}
}

// TestMergeManagedBlockMigratesLegacy:存在旧式无 key 块时,本实例 sync 顺带清掉旧块
// (迁移),但不动其它实例 key 的块与用户行。
func TestMergeManagedBlockMigratesLegacy(t *testing.T) {
	const keyA, keyB = "aaaa1111", "bbbb2222"
	legacy := cronLegacyBeginMarker + "\n0 9 * * * /legacy.sh\n" + cronLegacyEndMarker + "\n"
	existing := "MAILTO=root\n" + legacy +
		cronBeginMarker(keyA) + "\n0 3 * * * /a/job.sh\n" + cronEndMarker(keyA) + "\n"

	out := MergeManagedBlock(existing,
		RenderManagedBlock(keyB, []CronJobLine{{Expr: "* * * * *", Command: "/b/job.sh"}}), keyB)

	if strings.Contains(out, "/legacy.sh") || strings.Contains(out, cronLegacyBeginMarker) {
		t.Errorf("legacy unkeyed block must be migrated away:\n%s", out)
	}
	if !strings.Contains(out, "/a/job.sh") {
		t.Errorf("other instance A's block must survive migration:\n%s", out)
	}
	if !strings.Contains(out, "/b/job.sh") {
		t.Errorf("this instance B's block must be present:\n%s", out)
	}
	if !strings.Contains(out, "MAILTO=root") {
		t.Errorf("user line must be preserved:\n%s", out)
	}
}

// TestInstanceKeySanitizes:任意种子(含注入字符)产出的 key 恒为 [a-z0-9]+,
// 且据此渲染的托管区不含畸形/被注入的标记;相同种子稳定,不同种子不同。
func TestInstanceKeySanitizes(t *testing.T) {
	safe := regexp.MustCompile(`^[a-z0-9]+$`)
	seeds := []string{
		"",
		"/data/inst-a/xpanel.db",
		"/data/x;rm -rf /\n# === XPANEL-CRON BEGIN (managed:evil) ===",
		"a)b ===\n0 0 * * * rm -rf /",
		"Mixed/Case/With Spaces\tand%percent",
		"../../etc/(managed:x)",
	}
	for _, s := range seeds {
		k := InstanceKey(s)
		if !safe.MatchString(k) {
			t.Errorf("InstanceKey(%q)=%q not a [a-z0-9] token", s, k)
		}
		if InstanceKey(s) != k {
			t.Errorf("InstanceKey not deterministic for %q", s)
		}
		block := RenderManagedBlock(k, []CronJobLine{{Expr: "* * * * *", Command: "true"}})
		if strings.Count(block, "XPANEL-CRON BEGIN") != 1 || strings.Count(block, "XPANEL-CRON END") != 1 {
			t.Errorf("seed %q produced malformed block:\n%s", s, block)
		}
		if !strings.Contains(block, cronBeginMarker(k)) {
			t.Errorf("seed %q: rendered block missing well-formed keyed marker:\n%s", s, block)
		}
	}
	if InstanceKey("/data/a") == InstanceKey("/data/b") {
		t.Error("distinct seeds must yield distinct keys")
	}
}

func TestMergeManagedBlockEmptyExisting(t *testing.T) {
	const key = "abc123"
	managed := RenderManagedBlock(key, []CronJobLine{{ID: 1, Expr: "* * * * *", Command: "true"}})
	merged := MergeManagedBlock("", managed, key)
	if merged != managed {
		t.Errorf("empty crontab should yield just the managed block, got:\n%s", merged)
	}
}
