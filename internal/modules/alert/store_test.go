package alert

import (
	"testing"
)

func TestChannelSecretEncryptedAndMasked(t *testing.T) {
	ss := newTestStore(t)
	id, err := ss.createChannel(Channel{Name: "tg", Kind: ChannelTelegram, TelegramChatID: "123", Secret: "bot-token-secret"})
	if err != nil {
		t.Fatal(err)
	}

	// list/get 必须屏蔽 Secret(明文绝不回传),但标 HasSecret。
	got, err := ss.getChannel(id)
	if err != nil {
		t.Fatal(err)
	}
	if got.Secret != "" {
		t.Errorf("getChannel leaked secret: %q", got.Secret)
	}
	if !got.HasSecret {
		t.Error("HasSecret should be true")
	}

	// 落库列必须是密文,不含明文。
	var enc string
	if err := ss.db.QueryRow(`SELECT secret_enc FROM alert_channels WHERE id = ?`, id).Scan(&enc); err != nil {
		t.Fatal(err)
	}
	if enc == "" || enc == "bot-token-secret" {
		t.Errorf("secret stored in plaintext or empty: %q", enc)
	}

	// 内部取用须能解回明文。
	_, plain, err := ss.getChannelEnc(id)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "bot-token-secret" {
		t.Errorf("decrypted secret = %q, want bot-token-secret", plain)
	}
}

func TestUpdateChannelKeepsSecretWhenEmpty(t *testing.T) {
	ss := newTestStore(t)
	id, _ := ss.createChannel(Channel{Name: "wh", Kind: ChannelWebhook, WebhookURL: "http://x", Secret: "orig-token"})

	// 更新但 Secret 留空 → 保留原凭证。
	if err := ss.updateChannel(Channel{ID: id, Name: "wh2", Kind: ChannelWebhook, WebhookURL: "http://y"}); err != nil {
		t.Fatal(err)
	}
	_, plain, _ := ss.getChannelEnc(id)
	if plain != "orig-token" {
		t.Errorf("empty secret on update wiped credential: %q", plain)
	}

	// 更新且 Secret 非空 → 替换。
	if err := ss.updateChannel(Channel{ID: id, Name: "wh2", Kind: ChannelWebhook, WebhookURL: "http://y", Secret: "new-token"}); err != nil {
		t.Fatal(err)
	}
	_, plain, _ = ss.getChannelEnc(id)
	if plain != "new-token" {
		t.Errorf("secret not updated: %q", plain)
	}
}

func TestRuleCRUD(t *testing.T) {
	ss := newTestStore(t)
	chID, _ := ss.createChannel(Channel{Name: "ch", Kind: ChannelEmail, SMTPTo: "a@b"})
	id, err := ss.createRule(Rule{Name: "mem", Metric: "memory", Comparator: "gt", Threshold: 90, ChannelID: chID, Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	got, err := ss.getRule(id)
	if err != nil || got.Name != "mem" || !got.Enabled {
		t.Fatalf("getRule = %+v, err %v", got, err)
	}

	got.Enabled = false
	got.Threshold = 95
	if err := ss.updateRule(got); err != nil {
		t.Fatal(err)
	}
	enabled, err := ss.listEnabledRules()
	if err != nil {
		t.Fatal(err)
	}
	if len(enabled) != 0 {
		t.Errorf("disabled rule still listed as enabled: %d", len(enabled))
	}

	if err := ss.deleteRule(id); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.getRule(id); err != errNotFound {
		t.Errorf("expected errNotFound after delete, got %v", err)
	}
}

func TestUpdateRuleNotFound(t *testing.T) {
	ss := newTestStore(t)
	err := ss.updateRule(Rule{ID: 999, Name: "x", Metric: "cpu", Comparator: "gt", ChannelID: 1})
	if err != errNotFound {
		t.Errorf("expected errNotFound, got %v", err)
	}
}

func TestSettingsRoundTrip(t *testing.T) {
	ss := newTestStore(t)
	// 默认值。
	def, _ := ss.loadSettings()
	if def != DefaultSettings() {
		t.Errorf("default settings = %+v, want %+v", def, DefaultSettings())
	}
	if err := ss.saveSettings(Settings{IntervalSec: 15, SilenceSec: 600}); err != nil {
		t.Fatal(err)
	}
	got, _ := ss.loadSettings()
	if got.IntervalSec != 15 || got.SilenceSec != 600 {
		t.Errorf("settings round-trip = %+v", got)
	}
}

func TestHistoryOrdering(t *testing.T) {
	ss := newTestStore(t)
	for i := 0; i < 3; i++ {
		if err := ss.addHistory(History{RuleName: "r", Metric: "cpu", FiredAt: int64(1000 + i)}); err != nil {
			t.Fatal(err)
		}
	}
	hs, _ := ss.listHistory(10)
	if len(hs) != 3 || hs[0].FiredAt != 1002 {
		t.Fatalf("history not newest-first: %+v", hs)
	}
}
