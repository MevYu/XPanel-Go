package appstore

import (
	"errors"
	"sync"
)

// mockCompose 记录所有 compose 调用,供 handler 测试断言,无真实 docker 副作用。
type mockCompose struct {
	mu sync.Mutex

	written    map[string]string // projectDir -> content
	upCalls    []string          // project names
	downCalls  []downCall
	stopCalls  []string
	startCalls []string
	removedDir []string

	availableErr error
	upErr        error
	downErr      error
	psOut        string
	logsOut      string
}

type downCall struct {
	project       string
	removeVolumes bool
}

func newMockCompose() *mockCompose {
	return &mockCompose{written: make(map[string]string)}
}

func (m *mockCompose) WriteProject(projectDir, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.written[projectDir] = content
	return nil
}

func (m *mockCompose) Up(project, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.upCalls = append(m.upCalls, project)
	return m.upErr
}

func (m *mockCompose) Down(project, _ string, removeVolumes bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.downCalls = append(m.downCalls, downCall{project, removeVolumes})
	return m.downErr
}

func (m *mockCompose) Stop(project, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopCalls = append(m.stopCalls, project)
	return nil
}

func (m *mockCompose) Start(project, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.startCalls = append(m.startCalls, project)
	return nil
}

func (m *mockCompose) PS(_, _ string) (string, error)        { return m.psOut, nil }
func (m *mockCompose) Logs(_, _ string, _ int) (string, error) { return m.logsOut, nil }

func (m *mockCompose) RemoveProjectDir(projectDir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removedDir = append(m.removedDir, projectDir)
	return nil
}

func (m *mockCompose) Available() error { return m.availableErr }

var errUnavailable = errors.New("unavailable")
