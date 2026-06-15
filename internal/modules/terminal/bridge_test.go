package terminal

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// TestBridgeEchoesShell 是一个轻量端到端检查:连真实 WS,起 PTY,
// 发一条 echo 命令,确认 shell 输出经 PTY 回到 WS。无 shell 则跳过。
func TestBridgeEchoesShell(t *testing.T) {
	if err := system.ShellAvailable(); err != nil {
		t.Skipf("no shell available: %v", err)
	}
	m := New(fakeDeps("operator", new(int)))
	srv := httptest.NewServer(http.HandlerFunc(m.handleWS))
	defer srv.Close()

	tok := m.tickets.issue(1, "operator")
	wsURL := "ws" + srv.URL[len("http"):] + "/?ticket=" + tok

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	marker := []byte("XPANEL_TERMINAL_OK")
	if err := c.Write(ctx, websocket.MessageBinary, append([]byte("echo "), append(marker, '\n')...)); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if bytes.Contains(data, marker) {
			return // shell 回显到达,桥接通
		}
	}
	t.Fatal("did not observe shell echo within deadline")
}
