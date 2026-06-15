package alert

import (
	"context"
	"fmt"
	"log"
	"time"
)

// ruleState 跟踪一条规则的运行态:连续超阈值的起点与上次发通知的时间。
type ruleState struct {
	firingSince time.Time // 持续触发的起始时刻;零值表示当前未触发
	lastNotify  time.Time // 上次发通知时刻;用于静默期去重
}

// evaluator 持有跨周期的规则状态并执行一轮评估。非并发使用(只在后台单 goroutine 内跑)。
type evaluator struct {
	store   *alertStore
	now     func() time.Time                  // 可注入,便于测试时间推进
	resolve func(ChannelKind) (Sender, error) // 可注入,测试用 mock 替换真实 sender
	states  map[int64]*ruleState
	prev    sample // 上一轮采样,供 disk_io 速率差分
}

func newEvaluator(store *alertStore) *evaluator {
	return &evaluator{store: store, now: time.Now, resolve: senderFor, states: map[int64]*ruleState{}}
}

// evaluateOnce 跑一轮:采集指标、检查所有启用规则、按持续时间与静默期决定是否发通知。
// 返回本轮实际发出的通知数(便于测试断言)。
func (e *evaluator) evaluateOnce(ctx context.Context) (int, error) {
	cur, err := collectSample()
	if err != nil {
		return 0, err
	}
	n := e.evaluateSample(ctx, cur)
	e.prev = cur
	return n, nil
}

// evaluateSample 用给定采样跑一轮评估(逻辑核心,测试直接喂造的 sample)。
func (e *evaluator) evaluateSample(ctx context.Context, cur sample) int {
	set, err := e.store.loadSettings()
	if err != nil {
		log.Printf("alert: load settings failed: %v", err)
		set = DefaultSettings()
	}
	rules, err := e.store.listEnabledRules()
	if err != nil {
		log.Printf("alert: list rules failed: %v", err)
		return 0
	}
	now := e.now()
	sent := 0
	live := map[int64]bool{}
	for _, r := range rules {
		live[r.ID] = true
		st := e.states[r.ID]
		if st == nil {
			st = &ruleState{}
			e.states[r.ID] = st
		}
		value := metricValue(Metric(r.Metric), cur, e.prev)
		if !r.firing(value) {
			st.firingSince = time.Time{} // 恢复正常,清空持续计时
			continue
		}
		if st.firingSince.IsZero() {
			st.firingSince = now
		}
		// 未达持续时间要求,先不触发。
		if now.Sub(st.firingSince) < time.Duration(r.DurationSec)*time.Second {
			continue
		}
		// 静默期内已通知过,去重(只记历史不再发)。
		silenced := !st.lastNotify.IsZero() && now.Sub(st.lastNotify) < time.Duration(set.SilenceSec)*time.Second
		notified := false
		if !silenced {
			if err := e.notify(ctx, r, value); err != nil {
				log.Printf("alert: notify rule %d failed: %v", r.ID, err)
			} else {
				notified = true
				st.lastNotify = now
				sent++
			}
		}
		e.recordHistory(r, value, notified, silenced)
	}
	// 删除已不存在(被删/停用)规则的状态,避免泄漏。
	for id := range e.states {
		if !live[id] {
			delete(e.states, id)
		}
	}
	return sent
}

// notify 取规则关联渠道(解密凭证)并发送。
func (e *evaluator) notify(ctx context.Context, r Rule, value float64) error {
	ch, secret, err := e.store.getChannelEnc(r.ChannelID)
	if err != nil {
		return err
	}
	sender, err := e.resolve(ch.Kind)
	if err != nil {
		return err
	}
	return sender.Send(ctx, ch, secret, notificationFor(r, value))
}

func (e *evaluator) recordHistory(r Rule, value float64, notified, silenced bool) {
	detail := fmt.Sprintf("%s %s %.2f (=%.2f)", r.Metric, r.Comparator, r.Threshold, value)
	if silenced {
		detail += " [silenced]"
	}
	h := History{
		RuleID:    r.ID,
		RuleName:  r.Name,
		Metric:    r.Metric,
		Value:     value,
		Threshold: r.Threshold,
		Notified:  notified,
		Detail:    detail,
		FiredAt:   e.now().Unix(),
	}
	if err := e.store.addHistory(h); err != nil {
		log.Printf("alert: record history failed: %v", err)
	}
}

// notificationFor 组装一条告警的主题与正文。
func notificationFor(r Rule, value float64) Notification {
	return Notification{
		Subject: fmt.Sprintf("[XPanel 告警] %s", r.Name),
		Body: fmt.Sprintf("规则 %q 触发:指标 %s 当前值 %.2f %s 阈值 %.2f。",
			r.Name, r.Metric, value, r.Comparator, r.Threshold),
	}
}
