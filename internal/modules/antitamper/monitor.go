package antitamper

import (
	"context"
	"log"
	"sync"
	"time"
)

// monitor 是后台周期扫描器:对受保护目录做基线对比,检出篡改记事件并增量更新基线。
// 由 context 驱动,Stop 取消 ctx 后 run 循环干净退出。
type monitor struct {
	st     *atStore
	alert  func(Change) // 可选告警 hook;nil 表示不告警
	cancel context.CancelFunc
	done   chan struct{}
	mu     sync.Mutex // 保护 cancel/done(Start/Stop 可能并发)
}

func newMonitor(st *atStore, alert func(Change)) *monitor {
	return &monitor{st: st, alert: alert}
}

// start 起后台 goroutine 并立即返回。重复 start 先停旧再起新(幂等)。
func (m *monitor) start(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cancel != nil {
		return // 已在运行
	}
	cctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	m.done = make(chan struct{})
	go m.run(cctx, m.done)
}

// stop 取消 ctx 并等待 run 退出(无 goroutine 泄漏)。
func (m *monitor) stop() {
	m.mu.Lock()
	cancel, done := m.cancel, m.done
	m.cancel, m.done = nil, nil
	m.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// run 是后台循环:按设置的间隔扫描,ctx 取消即退出。间隔从设置实时读取。
func (m *monitor) run(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	for {
		interval := m.interval()
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			if err := m.scanOnce(ctx); err != nil {
				log.Printf("antitamper: scan failed: %v", err)
			}
		}
	}
}

// interval 取当前配置的扫描间隔(秒),非法值回落到默认。
func (m *monitor) interval() time.Duration {
	s, err := m.st.getSettings()
	if err != nil || s.IntervalSec <= 0 {
		return time.Duration(defaultSettings().IntervalSec) * time.Second
	}
	return time.Duration(s.IntervalSec) * time.Second
}

// scanOnce 执行一轮:对每个受保护目录扫描当前指纹,与基线对比,
// 记事件、触发告警、增量更新基线。暂停时跳过(只读监控,绝不执行被监控文件)。
func (m *monitor) scanOnce(ctx context.Context) error {
	s, err := m.st.getSettings()
	if err != nil {
		return err
	}
	if s.Paused {
		return nil
	}
	base, err := m.st.baseline()
	if err != nil {
		return err
	}
	if len(base) == 0 {
		// 未建立基线:不把全树当作新增告警,等管理员显式重建基线。
		return nil
	}
	cur := map[string]FileState{}
	for _, dir := range s.ProtectedDirs {
		if err := ctx.Err(); err != nil {
			return err // Stop() 取消时及时退出,不被慢扫描拖住
		}
		states, serr := ScanTree(ctx, dir, s.ExcludeRules)
		if serr != nil {
			log.Printf("antitamper: scan dir %q: %v", dir, serr)
			continue
		}
		for p, st := range states {
			cur[p] = st
		}
	}
	changes := Diff(base, cur)
	if len(changes) == 0 {
		return nil
	}
	if err := m.st.recordEvents(changes); err != nil {
		return err
	}
	if m.alert != nil {
		for _, c := range changes {
			m.alert(c)
		}
	}
	return m.st.applyChanges(cur, changes)
}
