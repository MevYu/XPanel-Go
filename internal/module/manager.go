package module

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/MevYu/XPanel-Go/internal/store"
)

// ValidationError 表示用户可安全展示的校验失败(未知 id / 依赖未满足 / AlwaysOn / 被依赖占用),不含内部敏感信息。
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

// Manager 编排模块启用/停用:依赖校验、健康检查、Start/Stop、状态持久化与重启恢复。
type Manager struct {
	reg   *Registry
	store *store.Store

	mu      sync.RWMutex
	enabled map[string]bool
}

func NewManager(reg *Registry, st *store.Store) *Manager {
	return &Manager{reg: reg, store: st, enabled: make(map[string]bool)}
}

func (mgr *Manager) IsEnabled(id string) bool {
	mgr.mu.RLock()
	defer mgr.mu.RUnlock()
	return mgr.enabled[id]
}

// Enable 校验依赖 → HealthCheck → Start → 持久化。任一步失败则不改变状态。
func (mgr *Manager) Enable(id string) error {
	m, ok := mgr.reg.Get(id)
	if !ok {
		return &ValidationError{Msg: fmt.Sprintf("module: unknown id %q", id)}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if mgr.enabled[id] {
		return nil
	}
	for _, dep := range m.Meta().Requires {
		if !mgr.enabled[dep] {
			return &ValidationError{Msg: fmt.Sprintf("module %q requires %q to be enabled first", id, dep)}
		}
	}
	if err := m.HealthCheck(); err != nil {
		// HealthCheck 失败原因(缺 nginx/docker 连不上等)对用户可见、可操作,非内部敏感信息 → 放给前端。
		return &ValidationError{Msg: fmt.Sprintf("模块 %q 依赖不满足: %v", id, err)}
	}
	if err := m.Start(context.Background()); err != nil {
		return fmt.Errorf("module %q start failed: %w", id, err)
	}
	if err := mgr.store.SetModuleEnabled(id, true); err != nil {
		// 回滚已启动的后台任务;Stop 错误并入返回值,以便诊断"已启动但标记为停用"的状态泄漏。
		return errors.Join(err, m.Stop(context.Background()))
	}
	mgr.enabled[id] = true
	return nil
}

// Disable 若被其他已启用模块依赖则拒绝;否则 Stop → 持久化。AlwaysOn 不可停用。
func (mgr *Manager) Disable(id string) error {
	m, ok := mgr.reg.Get(id)
	if !ok {
		return &ValidationError{Msg: fmt.Sprintf("module: unknown id %q", id)}
	}
	if m.Meta().AlwaysOn {
		return &ValidationError{Msg: fmt.Sprintf("module %q is always-on and cannot be disabled", id)}
	}
	mgr.mu.Lock()
	defer mgr.mu.Unlock()
	if !mgr.enabled[id] {
		return nil
	}
	for _, other := range mgr.reg.All() {
		if !mgr.enabled[other.Meta().ID] {
			continue
		}
		for _, dep := range other.Meta().Requires {
			if dep == id {
				return &ValidationError{Msg: fmt.Sprintf("module %q is required by %q", id, other.Meta().ID)}
			}
		}
	}
	if err := m.Stop(context.Background()); err != nil {
		return fmt.Errorf("module %q stop failed: %w", id, err)
	}
	if err := mgr.store.SetModuleEnabled(id, false); err != nil {
		return err
	}
	mgr.enabled[id] = false
	return nil
}

// Restore 启动时调用:启用 AlwaysOn 与上次持久化为 enabled 的模块。
// 不依赖注册顺序——反复扫描,每轮启用依赖已满足的模块,直至无剩余或无进展。
func (mgr *Manager) Restore() error {
	persisted, err := mgr.store.EnabledModules()
	if err != nil {
		return err
	}
	want := make(map[string]bool)
	for _, m := range mgr.reg.All() {
		id := m.Meta().ID
		if m.Meta().AlwaysOn || persisted[id] {
			want[id] = true
		}
	}
	for len(want) > 0 {
		progressed := false
		for id := range want {
			m, _ := mgr.reg.Get(id)
			ready := true
			for _, dep := range m.Meta().Requires {
				if !mgr.IsEnabled(dep) {
					ready = false
					break
				}
			}
			if !ready {
				continue
			}
			if err := mgr.Enable(id); err != nil {
				return fmt.Errorf("restore %q: %w", id, err)
			}
			delete(want, id)
			progressed = true
		}
		if !progressed {
			return errors.New("restore: unsatisfiable module dependencies")
		}
	}
	return nil
}
