package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/MevYu/XPanel-Go/internal/auth"
	"github.com/MevYu/XPanel-Go/internal/config"
	"github.com/MevYu/XPanel-Go/internal/server"
	"github.com/MevYu/XPanel-Go/internal/store"
)

const version = "0.0.1"

func main() {
	cfg, err := config.Load("config.json")
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DBPath), 0o700); err != nil {
		log.Fatalf("mkdir data: %v", err)
	}

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	defer st.Close()

	secret, _ := base64.StdEncoding.DecodeString(cfg.JWTSecret)
	jm := auth.NewJWTManager(secret)
	lo := auth.NewLockout(5, 5*time.Minute, time.Now)
	svc := auth.NewService(st, jm, lo)

	// 首启:无用户则创建 admin,随机密码打印到 stdout(仅此一次)
	if n, _ := st.CountUsers(); n == 0 {
		pw := randomPassword()
		if err := svc.Register("admin", pw, "admin"); err != nil {
			log.Fatalf("bootstrap admin: %v", err)
		}
		fmt.Printf("==== XPanel 首次启动 ====\n用户名: admin\n密码: %s\n(请立即登录并修改)\n", pw)
	}

	h := server.New(svc, jm)
	fmt.Printf("XPanel %s 监听 https-ready http://%s\n", version, cfg.Addr)
	log.Fatal(http.ListenAndServe(cfg.Addr, h))
}

func randomPassword() string {
	b := make([]byte, 12)
	_, _ = randRead(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randRead(b []byte) (int, error) { return rand.Read(b) }
