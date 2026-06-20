package cron

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// buildLogCutPath 复现 runner 对 log_cut 路径的 SafeJoin 限定,返回 root 内绝对路径。
func buildLogCutPath(t *testing.T, rel string) (string, error) {
	t.Helper()
	return system.SafeJoin(logCutRoot, rel)
}

// --- task type validation ---

func TestValidatePayload(t *testing.T) {
	root := t.TempDir()
	cases := []struct {
		name string
		typ  string
		in   payload
		ok   bool
	}{
		{"command ok", taskCommand, payload{Command: "/bin/x.sh"}, true},
		{"command empty", taskCommand, payload{Command: "  "}, false},
		{"command newline", taskCommand, payload{Command: "a\nb"}, false},
		{"command percent", taskCommand, payload{Command: "echo %s"}, false},
		{"shell ok", taskShell, payload{Script: "#!/bin/sh\necho hi\n"}, true},
		{"shell empty", taskShell, payload{Script: ""}, false},
		{"release mem", taskReleaseMem, payload{}, true},
		{"url ok", taskURL, payload{URL: "https://example.com/ping"}, true},
		{"url no scheme", taskURL, payload{URL: "example.com"}, false},
		{"url ftp", taskURL, payload{URL: "ftp://x/y"}, false},
		{"url bad timeout", taskURL, payload{URL: "http://x", Timeout: 99999}, false},
		{"logcut empty", taskLogCut, payload{Path: ""}, false},
		{"backup site ok", taskBackupSite, payload{Target: "my-site.com"}, true},
		{"backup site bad", taskBackupSite, payload{Target: "a;rm -rf"}, false},
		{"backup db ok mysql", taskBackupDB, payload{Target: "mysql:appdb"}, true},
		{"backup db ok postgres", taskBackupDB, payload{Target: "postgres:appdb"}, true},
		{"backup db no engine", taskBackupDB, payload{Target: "appdb"}, false},
		{"backup db bad engine", taskBackupDB, payload{Target: "sqlite:appdb"}, false},
		{"backup db bad name", taskBackupDB, payload{Target: "mysql:a;b"}, false},
		{"unknown", "wat", payload{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := validatePayload(c.typ, c.in, root)
			if c.ok && err != nil {
				t.Errorf("want ok, got %v", err)
			}
			if !c.ok && err == nil {
				t.Errorf("want error, got nil")
			}
		})
	}
}

func TestValidatePayloadLogCutOK(t *testing.T) {
	root := t.TempDir()
	if _, err := validatePayload(taskLogCut, payload{Path: "app/access.log"}, root); err != nil {
		t.Errorf("relative log path under root should be ok: %v", err)
	}
}

// --- url task create via friendly schedule ---

func TestCreateURLTaskWithSchedule(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "operator")
	body := `{"schedule":{"kind":"daily_at","hour":3,"minute":30},
		"type":"url","payload":{"url":"https://example.com/ping","timeout":15},
		"comment":"ping"}`
	rec := do(t, h, http.MethodPost, "/jobs", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create url task: want 201, got %d (%s)", rec.Code, rec.Body)
	}
	var j Job
	_ = json.Unmarshal(rec.Body.Bytes(), &j)
	if j.Type != taskURL || j.Expr != "30 3 * * *" || j.Payload.URL != "https://example.com/ping" {
		t.Errorf("unexpected job: %+v", j)
	}
	if j.Payload.Timeout != 15 {
		t.Errorf("timeout not stored: %+v", j.Payload)
	}
}

func TestCreateRejectsBadURL(t *testing.T) {
	fakeCrontab(t)
	_, h, _ := newTestModule(t, "operator")
	rec := do(t, h, http.MethodPost, "/jobs",
		`{"schedule":{"kind":"hourly_at","minute":0},"type":"url","payload":{"url":"javascript:alert(1)"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad url scheme: want 400, got %d", rec.Code)
	}
}

func TestLogCutPathClampedWithinRoot(t *testing.T) {
	// SafeJoin 把 "../../etc/shadow" / 绝对路径中和到 root 子树内,不逃逸。
	abs, err := buildLogCutPath(t, "../../etc/shadow")
	if err != nil {
		t.Fatalf("expected clamp not error: %v", err)
	}
	if !strings.HasPrefix(abs, logCutRoot) {
		t.Errorf("log_cut path escaped root: %q", abs)
	}
	abs, err = buildLogCutPath(t, "/etc/shadow")
	if err != nil {
		t.Fatalf("absolute path should clamp: %v", err)
	}
	if !strings.HasPrefix(abs, logCutRoot) {
		t.Errorf("absolute path not clamped under root: %q", abs)
	}
}

// --- run now + run logs (mock runner) ---

// mockRunner 返回预置结果,记录被调用的 job。
type mockRunner struct {
	res    runResult
	called []int64
}

func (m *mockRunner) run(_ context.Context, j Job) runResult {
	m.called = append(m.called, j.ID)
	r := m.res
	if r.StartedAt == 0 {
		r.StartedAt = time.Now().Unix()
	}
	return r
}

func TestRunNowRecordsResult(t *testing.T) {
	fakeCrontab(t)
	m, h, audits := newTestModule(t, "operator")
	mr := &mockRunner{res: runResult{ExitCode: 0, Output: "done", DurationMs: 12}}
	m.sched.run = mr

	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"0 3 * * *","command":"/bin/x.sh"}`)
	var j Job
	_ = json.Unmarshal(rec.Body.Bytes(), &j)

	rec = do(t, h, http.MethodPost, "/jobs/"+itoa(j.ID)+"/run", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("run now: want 200, got %d (%s)", rec.Code, rec.Body)
	}
	var got runRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.ExitCode != 0 || got.Output != "done" {
		t.Errorf("unexpected run result: %+v", got)
	}
	if len(mr.called) != 1 || mr.called[0] != j.ID {
		t.Errorf("runner not invoked for job: %v", mr.called)
	}

	// runs 端点能读到这次执行。
	rec = do(t, h, http.MethodGet, "/jobs/"+itoa(j.ID)+"/runs", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("runs: want 200, got %d", rec.Code)
	}
	var runs []runRecord
	_ = json.Unmarshal(rec.Body.Bytes(), &runs)
	if len(runs) != 1 || runs[0].Output != "done" {
		t.Errorf("runs endpoint missing record: %+v", runs)
	}

	var sawRun bool
	for _, a := range *audits {
		if strings.HasPrefix(a, "cron.run:") {
			sawRun = true
		}
	}
	if !sawRun {
		t.Errorf("run audit not written: %v", *audits)
	}
}

func TestRunNowRequiresOperator(t *testing.T) {
	fakeCrontab(t)
	m, h, _ := newTestModule(t, "operator")
	m.sched.run = &mockRunner{}
	rec := do(t, h, http.MethodPost, "/jobs", `{"expr":"0 3 * * *","command":"/bin/x.sh"}`)
	var j Job
	_ = json.Unmarshal(rec.Body.Bytes(), &j)

	// 切到 viewer 重新建模块共享同一 DB 不便;直接验证 viewer 模块拒绝。
	_, hv, _ := newTestModule(t, "viewer")
	rec = do(t, hv, http.MethodPost, "/jobs/"+itoa(j.ID)+"/run", "")
	if rec.Code != http.StatusForbidden {
		t.Errorf("viewer run now: want 403, got %d", rec.Code)
	}
}

func TestRunsTrimmedToMax(t *testing.T) {
	cs := newTestStore(t)
	id, _ := cs.create(Job{Expr: "* * * * *", Type: taskCommand, Payload: payload{Command: "x"}, Enabled: true})
	for i := 0; i < maxRunsPerJob+10; i++ {
		if err := cs.recordRun(id, runResult{StartedAt: int64(i), ExitCode: 0}); err != nil {
			t.Fatalf("recordRun: %v", err)
		}
	}
	runs, err := cs.runs(id, 0)
	if err != nil {
		t.Fatalf("runs: %v", err)
	}
	if len(runs) != maxRunsPerJob {
		t.Errorf("want %d runs after trim, got %d", maxRunsPerJob, len(runs))
	}
	// 最新的在前。
	if runs[0].StartedAt <= runs[len(runs)-1].StartedAt {
		t.Errorf("runs not descending: %d..%d", runs[0].StartedAt, runs[len(runs)-1].StartedAt)
	}
}

func TestDeleteCascadesRuns(t *testing.T) {
	cs := newTestStore(t)
	id, _ := cs.create(Job{Expr: "* * * * *", Type: taskCommand, Payload: payload{Command: "x"}, Enabled: true})
	_ = cs.recordRun(id, runResult{StartedAt: 1, ExitCode: 0})
	if err := cs.delete(id); err != nil {
		t.Fatalf("delete: %v", err)
	}
	runs, _ := cs.runs(id, 0)
	if len(runs) != 0 {
		t.Errorf("runs should be deleted with job, got %d", len(runs))
	}
}

// --- scheduler ---

func TestSchedulerTickRunsDueJobs(t *testing.T) {
	cs := newTestStore(t)
	due, _ := cs.create(Job{Expr: "30 9 * * *", Type: taskCommand, Payload: payload{Command: "x"}, Enabled: true})
	notDue, _ := cs.create(Job{Expr: "0 0 * * *", Type: taskCommand, Payload: payload{Command: "y"}, Enabled: true})
	disabled, _ := cs.create(Job{Expr: "30 9 * * *", Type: taskCommand, Payload: payload{Command: "z"}, Enabled: false})

	mr := &mockRunner{res: runResult{ExitCode: 0}}
	s := newScheduler(cs, mr)
	s.tick(time.Date(2026, 6, 15, 9, 30, 0, 0, time.UTC))

	if len(mr.called) != 1 || mr.called[0] != due {
		t.Fatalf("expected only due job %d to run, got %v", due, mr.called)
	}
	_ = notDue
	_ = disabled

	// 执行被记录。
	runs, _ := cs.runs(due, 0)
	if len(runs) != 1 {
		t.Errorf("due job should have 1 run record, got %d", len(runs))
	}
}

func TestSchedulerStartStopIdempotent(t *testing.T) {
	cs := newTestStore(t)
	s := newScheduler(cs, &mockRunner{})
	s.start()
	s.start() // 第二次无副作用
	s.stopLoop()
	s.stopLoop() // 第二次无副作用
}
