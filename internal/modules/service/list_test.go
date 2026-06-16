package service

import (
	"reflect"
	"testing"
)

// 真实 systemctl list-units --type=service --all --no-pager --plain 样本:
// 列 UNIT LOAD ACTIVE SUB DESCRIPTION,末尾有空行 + 图例需被忽略。
const sampleListUnits = `nginx.service                  loaded active   running Web Server
ssh.service                    loaded active   running OpenBSD Secure Shell server
cron.service                   loaded active   exited  Regular background program
broken.service                 loaded failed   failed  A broken unit with spaces
dead.service                   loaded inactive dead    A stopped unit

Legend: LOAD   = Reflects whether the unit definition was properly loaded.
        ACTIVE = The high-level unit activation state.

5 loaded units listed.
`

// systemctl list-unit-files --type=service --no-pager --plain 样本:
// 列 UNIT FILE STATE [VENDOR PRESET],映射 unit -> enabled 状态。
const sampleListUnitFiles = `nginx.service                  enabled  enabled
ssh.service                    enabled  enabled
cron.service                   enabled  enabled
broken.service                 disabled disabled
syslog.service                 static   -

5 unit files listed.
`

func TestParseListUnits(t *testing.T) {
	got := parseListUnits(sampleListUnits)
	want := map[string]Service{
		"nginx.service":  {Name: "nginx.service", Active: "active", Sub: "running", Description: "Web Server"},
		"ssh.service":    {Name: "ssh.service", Active: "active", Sub: "running", Description: "OpenBSD Secure Shell server"},
		"cron.service":   {Name: "cron.service", Active: "active", Sub: "exited", Description: "Regular background program"},
		"broken.service": {Name: "broken.service", Active: "failed", Sub: "failed", Description: "A broken unit with spaces"},
		"dead.service":   {Name: "dead.service", Active: "inactive", Sub: "dead", Description: "A stopped unit"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseListUnits mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestParseListUnitsSkipsHeaderless(t *testing.T) {
	// 无前导图例,空行后即止;含制表对齐的不规则空白。
	in := "a.service loaded active running A\n\njunk line should be ignored\n"
	got := parseListUnits(in)
	if len(got) != 1 {
		t.Fatalf("want 1 unit, got %d: %+v", len(got), got)
	}
	if got["a.service"].Active != "active" {
		t.Errorf("a.service active mismatch: %+v", got["a.service"])
	}
}

func TestParseListUnitFiles(t *testing.T) {
	got := parseListUnitFiles(sampleListUnitFiles)
	want := map[string]string{
		"nginx.service":  "enabled",
		"ssh.service":    "enabled",
		"cron.service":   "enabled",
		"broken.service": "disabled",
		"syslog.service": "static",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseListUnitFiles mismatch:\n got=%+v\nwant=%+v", got, want)
	}
}

func TestMergeServicesAttachesEnabled(t *testing.T) {
	units := parseListUnits(sampleListUnits)
	files := parseListUnitFiles(sampleListUnitFiles)
	got := mergeServices(units, files)

	byName := map[string]Service{}
	for _, s := range got {
		byName[s.Name] = s
	}
	if byName["nginx.service"].Enabled != "enabled" {
		t.Errorf("nginx enabled mismatch: %q", byName["nginx.service"].Enabled)
	}
	if byName["broken.service"].Enabled != "disabled" {
		t.Errorf("broken enabled mismatch: %q", byName["broken.service"].Enabled)
	}
	// dead.service 有 unit 但无 unit-file 条目 -> enabled 为空字符串,不报错。
	if byName["dead.service"].Enabled != "" {
		t.Errorf("dead enabled should be empty, got %q", byName["dead.service"].Enabled)
	}
	// 结果按 name 排序,稳定输出。
	for i := 1; i < len(got); i++ {
		if got[i-1].Name > got[i].Name {
			t.Fatalf("result not sorted by name: %q before %q", got[i-1].Name, got[i].Name)
		}
	}
}

func TestListServicesParsesFromRunner(t *testing.T) {
	r := &fakeRunner{units: sampleListUnits, files: sampleListUnitFiles}
	got, err := listServices(r)
	if err != nil {
		t.Fatalf("listServices: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("want 5 services, got %d", len(got))
	}
}

func TestListServicesPropagatesRunnerError(t *testing.T) {
	r := &fakeRunner{unitsErr: errBoom}
	if _, err := listServices(r); err == nil {
		t.Fatal("listServices must surface runner error")
	}
}
