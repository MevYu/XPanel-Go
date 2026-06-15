package dns

import (
	"context"
	"sync"
)

// Record 是一条 DNS 记录。ID 由记录表(store)分配,后端只负责把记录集落地。
type Record struct {
	ID       int64  `json:"id"`
	Name     string `json:"name"`     // 相对 zone 的子名,"@" 表 apex
	Type     string `json:"type"`     // A/AAAA/CNAME/MX/TXT/NS/SRV/CAA
	Value    string `json:"value"`    // 记录值(按类型语义)
	TTL      int    `json:"ttl"`      // 秒
	Priority int    `json:"priority"` // MX/SRV 用,其它为 0
}

// backend 抽象一个 DNS 数据面:本地 bind(渲染 zone 文件 + rndc reload)或云 provider(推送 API)。
// store 是记录的真相源;backend 只负责把某 zone 的完整记录集"应用"到数据面。
// 业务层只依赖此接口,便于 mock 测试与多后端切换。
type backend interface {
	// apply 把 zone 的完整记录集落地(全量覆盖)。records 已通过校验。
	apply(ctx context.Context, zone string, records []Record) error
	// healthy 自检后端是否可用(bind: rndc 存在+目录可写;云: 凭证已配置)。
	healthy() error
	// kind 返回后端类型标识,用于审计/展示。
	kind() string
}

// mockProvider 是内存型示例 provider:既作单测替身,也作"云 provider"接口的最小示例实现。
// 真实云 provider 复制此结构,把 applied 换成 SDK 推送即可;凭证由 settings 注入(已解密)。
type mockProvider struct {
	mu      sync.Mutex
	applied map[string][]Record // zone -> 最近一次 apply 的记录集
	creds   string              // 注入的已解密 API 凭证;为空表示未配置
}

// newMockProvider 用注入凭证构造示例 provider。
func newMockProvider(creds string) *mockProvider {
	return &mockProvider{applied: map[string][]Record{}, creds: creds}
}

func (*mockProvider) kind() string { return "mock" }

// healthy:无凭证不可用(避免误以为已接入云端)。
func (p *mockProvider) healthy() error {
	if p.creds == "" {
		return errNoCreds
	}
	return nil
}

func (p *mockProvider) apply(_ context.Context, zone string, records []Record) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	cp := make([]Record, len(records))
	copy(cp, records)
	p.applied[zone] = cp
	return nil
}
