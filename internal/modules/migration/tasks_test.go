package migration

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// taskIDFromBody 解析 202 响应体里的 {"task_id": N}。
func taskIDFromBody(t *testing.T, body []byte) int64 {
	t.Helper()
	var resp struct {
		TaskID int64 `json:"task_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("parse task_id: %v (body=%s)", err, body)
	}
	if resp.TaskID <= 0 {
		t.Fatalf("missing task_id in body %s", body)
	}
	return resp.TaskID
}

// waitTask 有界轮询任务直到终态(success/failed),超时即失败。
func waitTask(t *testing.T, m *Module, id int64) Task {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		task, err := m.ms.getTask(id)
		if err != nil {
			t.Fatalf("getTask(%d): %v", id, err)
		}
		if task.Status == "success" || task.Status == "failed" {
			return task
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("task %d did not reach terminal state in time", id)
	return Task{}
}

// --- store lifecycle ---

func TestTaskLifecycle(t *testing.T) {
	m := testModule(t, "admin", new(int))

	task, err := m.ms.createTask("export")
	if err != nil {
		t.Fatal(err)
	}
	if task.Status != "pending" || task.Progress != 0 {
		t.Fatalf("created task should be pending/0, got %+v", task)
	}

	if err := m.ms.updateTaskRunning(task.ID); err != nil {
		t.Fatal(err)
	}
	got, _ := m.ms.getTask(task.ID)
	if got.Status != "running" || got.StartedAt == 0 {
		t.Fatalf("running task wrong: %+v", got)
	}

	if err := m.ms.updateTaskProgress(task.ID, 50, "halfway"); err != nil {
		t.Fatal(err)
	}
	got, _ = m.ms.getTask(task.ID)
	if got.Progress != 50 || got.Message != "halfway" {
		t.Fatalf("progress update wrong: %+v", got)
	}

	if err := m.ms.finishTask(task.ID, "success", "out.tar.gz"); err != nil {
		t.Fatal(err)
	}
	got, _ = m.ms.getTask(task.ID)
	if got.Status != "success" || got.Progress != 100 || got.FinishedAt == 0 || got.Message != "out.tar.gz" {
		t.Fatalf("finished(success) wrong: %+v", got)
	}
}

func TestFinishTaskFailed(t *testing.T) {
	m := testModule(t, "admin", new(int))
	task, _ := m.ms.createTask("import")
	if err := m.ms.finishTask(task.ID, "failed", "boom"); err != nil {
		t.Fatal(err)
	}
	got, _ := m.ms.getTask(task.ID)
	if got.Status != "failed" || got.Message != "boom" || got.FinishedAt == 0 {
		t.Fatalf("finished(failed) wrong: %+v", got)
	}
}

func TestListTasksNewestFirst(t *testing.T) {
	m := testModule(t, "admin", new(int))
	t1, _ := m.ms.createTask("export")
	t2, _ := m.ms.createTask("import")
	list, err := m.ms.listTasks()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 tasks, got %d", len(list))
	}
	if list[0].ID != t2.ID || list[1].ID != t1.ID {
		t.Fatalf("expected newest-first [%d,%d], got [%d,%d]", t2.ID, t1.ID, list[0].ID, list[1].ID)
	}
}

// --- failing export marks task failed, records no package ---

func TestExportTaskFailsRecordsNoPackage(t *testing.T) {
	m := testModule(t, "admin", new(int))
	mp := &mockPacker{packSize: 1}
	md := &mockDumper{err: errors.New("dump exploded")}
	m.pk, m.dmp = mp, md

	site := t.TempDir()
	_ = m.ms.saveSettings(Settings{MigrationDir: t.TempDir()})
	body, _ := json.Marshal(exportRequest{SitePath: site, DBKind: "mysql", DBName: "shop"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", bytes.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("export should 202, got %d", rec.Code)
	}
	task := waitTask(t, m, taskIDFromBody(t, rec.Body.Bytes()))
	if task.Status != "failed" || task.Message == "" || task.FinishedAt == 0 {
		t.Fatalf("failed export task wrong: %+v", task)
	}
	if list, _ := m.ms.listPackages(); len(list) != 0 {
		t.Errorf("failed export must not record a package, got %d", len(list))
	}
}

// --- tasks endpoints ---

func TestListTasksEndpoint(t *testing.T) {
	m := testModule(t, "admin", new(int))
	_, _ = m.ms.createTask("export")
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/tasks", nil))
	if rec.Code != 200 {
		t.Fatalf("list tasks should 200, got %d", rec.Code)
	}
	var list []Task
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 task, got %d", len(list))
	}
}

func TestListTasksRequiresAdmin(t *testing.T) {
	m := testModule(t, "operator", new(int))
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/tasks", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin list tasks should 403, got %d", rec.Code)
	}
}

func TestGetTaskEndpoint(t *testing.T) {
	m := testModule(t, "admin", new(int))
	task, _ := m.ms.createTask("export")
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/tasks/"+itoa(task.ID), nil))
	if rec.Code != 200 {
		t.Fatalf("get task should 200, got %d", rec.Code)
	}
	var got Task
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.ID != task.ID || got.Kind != "export" {
		t.Fatalf("get task wrong: %+v", got)
	}
}

func TestGetTaskRequiresAdmin(t *testing.T) {
	m := testModule(t, "operator", new(int))
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/tasks/1", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-admin get task should 403, got %d", rec.Code)
	}
}

func TestGetTaskUnknownIDNotFound(t *testing.T) {
	m := testModule(t, "admin", new(int))
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("GET", "/tasks/999", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown task id should 404, got %d", rec.Code)
	}
}

// --- Stop waits for in-flight goroutine ---

func TestStopWaitsForInFlightTask(t *testing.T) {
	m := testModule(t, "admin", new(int))
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	mp := &mockPacker{packSize: 7}
	md := &mockDumper{started: make(chan struct{}), release: make(chan struct{})}
	m.pk, m.dmp = mp, md

	site := t.TempDir()
	_ = m.ms.saveSettings(Settings{MigrationDir: t.TempDir()})
	body, _ := json.Marshal(exportRequest{SitePath: site, DBKind: "mysql", DBName: "shop"})
	rec := httptest.NewRecorder()
	router(m).ServeHTTP(rec, httptest.NewRequest("POST", "/export", bytes.NewReader(body)))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("export should 202, got %d", rec.Code)
	}
	id := taskIDFromBody(t, rec.Body.Bytes())

	<-md.started      // 任务已在跑(dump 内阻塞)
	close(md.release) // 放行,让任务体跑完

	if err := m.Stop(context.Background()); err != nil { // 必须等待 goroutine 收尾后返回
		t.Fatal(err)
	}
	// Stop 返回后 wg 已 drain,任务必已到终态。
	got, err := m.ms.getTask(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "success" {
		t.Fatalf("task should be success after Stop, got %+v", got)
	}
}
