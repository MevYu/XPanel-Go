package alert

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

// captureRT 记录最后一次请求体并返回固定状态码,绕开真实网络(但不绕 SSRF 守卫)。
type captureRT struct {
	body   []byte
	status int
}

func (rt *captureRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		rt.body, _ = io.ReadAll(req.Body)
	}
	status := rt.status
	if status == 0 {
		status = http.StatusOK
	}
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader("")),
		Header:     make(http.Header),
	}, nil
}

func TestSenderForChineseChannels(t *testing.T) {
	cases := []struct {
		kind ChannelKind
		want any
	}{
		{ChannelDingtalk, dingtalkSender{}},
		{ChannelWecom, wecomSender{}},
		{ChannelFeishu, feishuSender{}},
	}
	for _, tc := range cases {
		got, err := senderFor(tc.kind)
		if err != nil {
			t.Fatalf("senderFor(%q): %v", tc.kind, err)
		}
		switch tc.kind {
		case ChannelDingtalk:
			if _, ok := got.(dingtalkSender); !ok {
				t.Errorf("kind %q: got %T, want dingtalkSender", tc.kind, got)
			}
		case ChannelWecom:
			if _, ok := got.(wecomSender); !ok {
				t.Errorf("kind %q: got %T, want wecomSender", tc.kind, got)
			}
		case ChannelFeishu:
			if _, ok := got.(feishuSender); !ok {
				t.Errorf("kind %q: got %T, want feishuSender", tc.kind, got)
			}
		}
	}
}

func TestValidChannelKindChineseChannels(t *testing.T) {
	for _, k := range []ChannelKind{ChannelDingtalk, ChannelWecom, ChannelFeishu} {
		if !validChannelKind(k) {
			t.Errorf("validChannelKind(%q) = false, want true", k)
		}
	}
}

func TestChineseSenderPayloads(t *testing.T) {
	// 公网 IP 字面量满足 SSRF 守卫;自定义 transport 捕获请求体,不走真实网络。
	const url = "https://8.8.8.8/robot/send"
	n := Notification{Subject: "CPU high", Body: "value 95%"}
	wantText := "CPU high\n\nvalue 95%"

	cases := []struct {
		name    string
		newSend func(c *http.Client) Sender
		check   func(t *testing.T, m map[string]any)
	}{
		{
			name:    "dingtalk",
			newSend: func(c *http.Client) Sender { return dingtalkSender{client: c} },
			check: func(t *testing.T, m map[string]any) {
				if m["msgtype"] != "text" {
					t.Errorf("dingtalk msgtype = %v", m["msgtype"])
				}
				text, _ := m["text"].(map[string]any)
				if text["content"] != wantText {
					t.Errorf("dingtalk content = %v, want %q", text["content"], wantText)
				}
			},
		},
		{
			name:    "wecom",
			newSend: func(c *http.Client) Sender { return wecomSender{client: c} },
			check: func(t *testing.T, m map[string]any) {
				if m["msgtype"] != "text" {
					t.Errorf("wecom msgtype = %v", m["msgtype"])
				}
				text, _ := m["text"].(map[string]any)
				if text["content"] != wantText {
					t.Errorf("wecom content = %v, want %q", text["content"], wantText)
				}
			},
		},
		{
			name:    "feishu",
			newSend: func(c *http.Client) Sender { return feishuSender{client: c} },
			check: func(t *testing.T, m map[string]any) {
				if m["msg_type"] != "text" {
					t.Errorf("feishu msg_type = %v", m["msg_type"])
				}
				content, _ := m["content"].(map[string]any)
				if content["text"] != wantText {
					t.Errorf("feishu text = %v, want %q", content["text"], wantText)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &captureRT{}
			client := &http.Client{Transport: rt}
			ch := Channel{WebhookURL: url}
			if err := tc.newSend(client).Send(context.Background(), ch, "", n); err != nil {
				t.Fatalf("Send: %v", err)
			}
			var m map[string]any
			if err := json.Unmarshal(rt.body, &m); err != nil {
				t.Fatalf("posted body not JSON: %v (%s)", err, rt.body)
			}
			tc.check(t, m)

			// non-2xx -> error
			rt2 := &captureRT{status: http.StatusBadRequest}
			err := tc.newSend(&http.Client{Transport: rt2}).Send(context.Background(), ch, "", n)
			if err == nil {
				t.Errorf("%s: non-2xx response should error", tc.name)
			}
		})
	}
}

func TestBuildMailEncodesSubjectNoHeaderInjection(t *testing.T) {
	// Subject carries an attacker-controlled rule name attempting to inject a Bcc header.
	n := Notification{
		Subject: "alert\r\nBcc: attacker@evil.com",
		Body:    "body",
	}
	msg := string(buildMail("from@example.com", []string{"to@example.com"}, n))

	// The Subject value must be RFC 2047-encoded so the raw CRLF cannot start a new header.
	for _, line := range strings.Split(msg, "\r\n") {
		// No header line other than the (encoded) Subject may carry the payload.
		if strings.HasPrefix(strings.ToLower(line), "bcc:") {
			t.Fatalf("injected Bcc header leaked into message:\n%s", msg)
		}
		if strings.HasPrefix(line, "Subject:") && strings.Contains(line, "\n") {
			t.Fatalf("Subject header spans multiple lines:\n%s", msg)
		}
	}
	// Raw CRLF from the payload must not survive verbatim inside the header block.
	headerBlock := msg
	if i := strings.Index(msg, "\r\n\r\n"); i >= 0 {
		headerBlock = msg[:i]
	}
	if strings.Contains(headerBlock, "alert\r\nBcc:") {
		t.Fatalf("raw CRLF payload survived in header block:\n%s", headerBlock)
	}
}

func TestValidateChannelRejectsSMTPHeaderInjection(t *testing.T) {
	bad := []Channel{
		{Kind: ChannelEmail, Name: "x", SMTPTo: "ok@x.com\r\nBcc: evil@x.com"},
		{Kind: ChannelEmail, Name: "x", SMTPFrom: "ok@x.com\nBcc: evil@x.com"},
		{Kind: ChannelEmail, Name: "x", SMTPUser: "user\r\nfoo"},
	}
	for i, c := range bad {
		if err := validateChannel(c); err == nil {
			t.Errorf("bad SMTP channel %d accepted", i)
		}
	}
	ok := Channel{Kind: ChannelEmail, Name: "ok", SMTPTo: "a@x.com, b@x.com", SMTPFrom: "f@x.com", SMTPUser: "user"}
	if err := validateChannel(ok); err != nil {
		t.Errorf("valid SMTP channel rejected: %v", err)
	}
}

func TestValidateChannelRejectsSSRFWebhook(t *testing.T) {
	bad := []string{
		"http://127.0.0.1/hook",
		"http://localhost/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5/hook",
		"http://192.168.1.1/hook",
		"http://172.16.0.1/hook",
		"http://[::1]/hook",
		"file:///etc/passwd",
		"ftp://example.com/x",
		"http://[fc00::1]/hook",
	}
	for _, u := range bad {
		c := Channel{Kind: ChannelWebhook, Name: "x", WebhookURL: u}
		if err := validateChannel(c); err == nil {
			t.Errorf("SSRF webhook URL accepted: %s", u)
		}
	}
	// Public IP literal avoids DNS in the test sandbox; the point is it is not blocked.
	ok := Channel{Kind: ChannelWebhook, Name: "x", WebhookURL: "https://8.8.8.8/path"}
	if err := validateChannel(ok); err != nil {
		t.Errorf("valid webhook URL rejected: %v", err)
	}
}

func TestWebhookSenderRejectsSSRF(t *testing.T) {
	s := webhookSender{client: defaultHTTPClient()}
	for _, u := range []string{"http://127.0.0.1/hook", "http://169.254.169.254/x", "file:///etc/passwd"} {
		ch := Channel{Kind: ChannelWebhook, WebhookURL: u}
		err := s.Send(context.Background(), ch, "", Notification{Subject: "s", Body: "b"})
		if err == nil {
			t.Errorf("webhook Send to %s should be blocked", u)
		}
	}
}
