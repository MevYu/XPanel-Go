package terminal

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
	"time"
)

// ticketSession 是一张票据绑定的发起主体。WS 升级时据此还原 who,用于审计与会话归属。
type ticketSession struct {
	userID  int64
	role    string
	expires time.Time
}

// ticketStore 是内存中的短时一次性票据表。浏览器原生 WS 不能带 Authorization,
// 故先用面板认证换一张短时票据,WS 仅凭票据握手。票据一次性、过期即废。
type ticketStore struct {
	ttl   time.Duration
	now   func() time.Time
	mu    sync.Mutex
	items map[string]ticketSession
}

func newTicketStore(ttl time.Duration, now func() time.Time) *ticketStore {
	return &ticketStore{ttl: ttl, now: now, items: make(map[string]ticketSession)}
}

// issue 签发一张绑定 (userID, role) 的票据,顺带惰性清理过期项。
func (s *ticketStore) issue(userID int64, role string) string {
	tok := randomToken()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	s.items[tok] = ticketSession{userID: userID, role: role, expires: s.now().Add(s.ttl)}
	return tok
}

// consume 校验并销毁票据:未知/过期返回 false。用后即焚保证一次性。
func (s *ticketStore) consume(tok string) (ticketSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.items[tok]
	if !ok {
		return ticketSession{}, false
	}
	delete(s.items, tok)
	if s.now().After(sess.expires) {
		return ticketSession{}, false
	}
	return sess, true
}

func (s *ticketStore) len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.items)
}

// purgeLocked 删除已过期票据。调用方须持锁。
func (s *ticketStore) purgeLocked() {
	now := s.now()
	for tok, sess := range s.items {
		if now.After(sess.expires) {
			delete(s.items, tok)
		}
	}
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("terminal: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
