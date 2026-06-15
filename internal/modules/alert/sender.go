package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Notification 是要发出的告警内容。
type Notification struct {
	Subject string
	Body    string
}

// Sender 把通知投递到一个具体渠道。secret 是该渠道解密后的明文凭证
// (SMTP 密码 / webhook bearer token / telegram bot token)。
// 抽象成接口便于 mock 测试,不在测试里真发网络请求。
type Sender interface {
	Send(ctx context.Context, ch Channel, secret string, n Notification) error
}

// senderFor 按渠道类型选择 Sender。
func senderFor(kind ChannelKind) (Sender, error) {
	switch kind {
	case ChannelEmail:
		return emailSender{}, nil
	case ChannelWebhook:
		return webhookSender{client: defaultHTTPClient()}, nil
	case ChannelTelegram:
		return telegramSender{client: defaultHTTPClient()}, nil
	}
	return nil, fmt.Errorf("alert: unknown channel kind %q", kind)
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}

// emailSender 用 stdlib net/smtp 投递。secret 为 SMTP 登录密码(可空 → 不鉴权)。
type emailSender struct{}

func (emailSender) Send(_ context.Context, ch Channel, secret string, n Notification) error {
	if ch.SMTPHost == "" || ch.SMTPPort == 0 {
		return fmt.Errorf("alert: smtp host/port required")
	}
	to := splitRecipients(ch.SMTPTo)
	if len(to) == 0 {
		return fmt.Errorf("alert: smtp_to required")
	}
	addr := net.JoinHostPort(ch.SMTPHost, strconv.Itoa(ch.SMTPPort))
	var auth smtp.Auth
	if ch.SMTPUser != "" {
		auth = smtp.PlainAuth("", ch.SMTPUser, secret, ch.SMTPHost)
	}
	msg := buildMail(ch.SMTPFrom, to, n)
	return smtp.SendMail(addr, auth, ch.SMTPFrom, to, msg)
}

func buildMail(from string, to []string, n Notification) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	// RFC 2047 编码 Subject:任何 CR/LF 都会被编码,无法注入额外邮件头。
	b.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", n.Subject) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(n.Body)
	return []byte(b.String())
}

func splitRecipients(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// webhookSender POST JSON 到配置的 URL。secret 非空则作为 Bearer token。
type webhookSender struct{ client *http.Client }

func (s webhookSender) Send(ctx context.Context, ch Channel, secret string, n Notification) error {
	if ch.WebhookURL == "" {
		return fmt.Errorf("alert: webhook_url required")
	}
	if err := guardOutboundURL(ch.WebhookURL); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"subject": n.Subject, "body": n.Body})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ch.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	return doExpectOK(s.client, req)
}

// telegramSender 调 Bot sendMessage API。secret 为 bot token。
type telegramSender struct{ client *http.Client }

func (s telegramSender) Send(ctx context.Context, ch Channel, secret string, n Notification) error {
	if secret == "" || ch.TelegramChatID == "" {
		return fmt.Errorf("alert: telegram token and chat_id required")
	}
	api := "https://api.telegram.org/bot" + secret + "/sendMessage"
	form := url.Values{}
	form.Set("chat_id", ch.TelegramChatID)
	form.Set("text", n.Subject+"\n\n"+n.Body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, api, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doExpectOK(s.client, req)
}

// doExpectOK 发请求并要求 2xx,否则报错(不把 body 里可能含的 token 回显细节)。
func doExpectOK(client *http.Client, req *http.Request) error {
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("alert: notify failed with status %d", resp.StatusCode)
	}
	return nil
}

// validateChannel 校验渠道配置,拒绝邮件头注入与 SSRF 目标。
// 在 create/update 处调用,把不安全配置挡在落库之前。
func validateChannel(c Channel) error {
	switch c.Kind {
	case ChannelEmail:
		// To/From/User 直接拼进 SMTP 信封与邮件头,CR/LF 可注入额外头。
		for _, f := range []string{c.SMTPTo, c.SMTPFrom, c.SMTPUser} {
			if strings.ContainsAny(f, "\r\n") {
				return fmt.Errorf("alert: smtp fields must not contain newlines")
			}
		}
	case ChannelWebhook:
		if c.WebhookURL != "" {
			if err := guardOutboundURL(c.WebhookURL); err != nil {
				return err
			}
		}
	}
	return nil
}

// guardOutboundURL 拒绝非 http/https scheme,以及解析后落在私有/环回/链路本地
// 网段的主机,挡掉 SSRF(127/8、10/8、172.16/12、192.168/16、169.254/16、::1、fc00::/7 等)。
func guardOutboundURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("alert: invalid url")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("alert: url scheme must be http or https")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("alert: url host required")
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		// 无法解析的主机不放行:避免依赖发送时再解析到内网地址。
		return fmt.Errorf("alert: cannot resolve url host")
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return fmt.Errorf("alert: url host resolves to a disallowed address")
		}
	}
	return nil
}

// isBlockedIP 报告 ip 是否属于不应被外发请求触达的内部网段。
func isBlockedIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	return false
}
