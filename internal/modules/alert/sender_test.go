package alert

import (
	"context"
	"strings"
	"testing"
)

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
