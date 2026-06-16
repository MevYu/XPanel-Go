package cron

import (
	"context"
	"log"
	"sync"
	"time"
)

// scheduler 在进程内按分钟粒度评估启用任务的 cron 表达式,到点经 runner 执行并记录。
// 这样才能捕获每次执行的输出/退出码/耗时(crontab 自身做不到),即 aaPanel 的执行日志能力。
type scheduler struct {
	cs     *cronStore
	run    runner
	now    func() time.Time // 可注入,便于测试
	stop   chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
	active bool
}

func newScheduler(cs *cronStore, r runner) *scheduler {
	return &scheduler{cs: cs, run: r, now: time.Now}
}

// start 启动调度循环(幂等)。对齐到下一分钟边界后每分钟 tick 一次。
func (s *scheduler) start() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active {
		return
	}
	s.active = true
	s.stop = make(chan struct{})
	s.wg.Add(1)
	go s.loop()
}

// stopLoop 停止调度循环(幂等),等待在跑的 tick 收尾。
func (s *scheduler) stopLoop() {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	close(s.stop)
	s.mu.Unlock()
	s.wg.Wait()
}

func (s *scheduler) loop() {
	defer s.wg.Done()
	// 对齐到下一整分钟,避免漂移。
	next := s.now().Truncate(time.Minute).Add(time.Minute)
	timer := time.NewTimer(time.Until(next))
	defer timer.Stop()
	for {
		select {
		case <-s.stop:
			return
		case <-timer.C:
			s.tick(s.now())
			next = next.Add(time.Minute)
			timer.Reset(time.Until(next))
		}
	}
}

// tick 跑所有在 t 这一分钟应触发的启用任务。
func (s *scheduler) tick(t time.Time) {
	jobs, err := s.cs.enabled()
	if err != nil {
		log.Printf("cron: scheduler list enabled failed: %v", err)
		return
	}
	for _, j := range jobs {
		if CronMatches(j.Expr, t) {
			s.execute(j)
		}
	}
}

// execute 同步执行一个任务并记录结果。给每次执行 10 分钟硬上限,防卡死调度。
func (s *scheduler) execute(j Job) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	res := s.run.run(ctx, j)
	if err := s.cs.recordRun(j.ID, res); err != nil {
		log.Printf("cron: record run for job %d failed: %v", j.ID, err)
	}
}
