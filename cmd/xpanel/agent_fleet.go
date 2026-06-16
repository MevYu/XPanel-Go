//go:build fleet

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/MevYu/XPanel-Go/internal/modules/fleet"
)

// init 在 main 之前运行:若以 --mode=agent 启动,则进入 agent 循环并永不返回到
// 正常的 controller 启动路径。仅 -tags fleet 时编入。
func init() {
	cfg, ok := parseAgentArgs(os.Args[1:])
	if !ok {
		return
	}
	if cfg.controller == "" || cfg.token == "" {
		fmt.Fprintln(os.Stderr, "agent 模式需要 --controller=<addr> 与 --token=<tok>")
		os.Exit(2)
	}
	if err := fleet.RunAgent(cfg.controller, cfg.token, cfg.name, cfg.tags); err != nil {
		log.Fatalf("fleet agent: %v", err)
	}
	os.Exit(0)
}

type agentArgs struct {
	controller string
	token      string
	name       string
	tags       string
}

// parseAgentArgs 解析 --mode/--controller/--token/--name/--tags(支持 --k=v 与 --k v)。
// 返回 ok=false 表示非 agent 模式,走正常 controller 启动。
func parseAgentArgs(args []string) (agentArgs, bool) {
	var cfg agentArgs
	mode := ""
	for i := 0; i < len(args); i++ {
		key, val, hasEq := splitFlag(args[i])
		take := func() string {
			if hasEq {
				return val
			}
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch key {
		case "--mode":
			mode = take()
		case "--controller":
			cfg.controller = take()
		case "--token":
			cfg.token = take()
		case "--name":
			cfg.name = take()
		case "--tags":
			cfg.tags = take()
		}
	}
	if mode != "agent" {
		return agentArgs{}, false
	}
	return cfg, true
}

func splitFlag(arg string) (key, val string, hasEq bool) {
	for i := 0; i < len(arg); i++ {
		if arg[i] == '=' {
			return arg[:i], arg[i+1:], true
		}
	}
	return arg, "", false
}
