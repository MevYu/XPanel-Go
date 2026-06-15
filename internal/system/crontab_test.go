package system

import (
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
	out := RenderManagedBlock([]CronJobLine{
		{ID: 1, Expr: "0 3 * * *", Command: "/bin/backup.sh", Comment: "nightly backup"},
	})
	if !strings.Contains(out, cronBeginMarker) || !strings.Contains(out, cronEndMarker) {
		t.Fatal("managed block must contain begin/end markers")
	}
	if !strings.Contains(out, "0 3 * * * /bin/backup.sh") {
		t.Errorf("rendered block missing job line:\n%s", out)
	}
	if !strings.Contains(out, "# nightly backup") {
		t.Errorf("rendered block missing comment:\n%s", out)
	}
}

func TestRenderManagedBlockSanitizesComment(t *testing.T) {
	out := RenderManagedBlock([]CronJobLine{
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
	existing := "MAILTO=root\n0 1 * * * /user/own.sh\n" +
		cronBeginMarker + "\n0 9 * * * /old.sh\n" + cronEndMarker + "\n"
	managed := RenderManagedBlock([]CronJobLine{
		{ID: 2, Expr: "0 10 * * *", Command: "/new.sh"},
	})
	merged := MergeManagedBlock(existing, managed)

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
	if strings.Count(merged, cronBeginMarker) != 1 {
		t.Errorf("expected exactly one managed block, got:\n%s", merged)
	}
}

func TestMergeManagedBlockAppendsWhenNone(t *testing.T) {
	existing := "0 1 * * * /user/own.sh\n"
	managed := RenderManagedBlock(nil)
	merged := MergeManagedBlock(existing, managed)
	if !strings.Contains(merged, "/user/own.sh") {
		t.Error("user line lost")
	}
	if strings.Count(merged, cronBeginMarker) != 1 {
		t.Error("managed block should be appended exactly once")
	}
}

func TestMergeManagedBlockEmptyExisting(t *testing.T) {
	managed := RenderManagedBlock([]CronJobLine{{ID: 1, Expr: "* * * * *", Command: "true"}})
	merged := MergeManagedBlock("", managed)
	if merged != managed {
		t.Errorf("empty crontab should yield just the managed block, got:\n%s", merged)
	}
}
