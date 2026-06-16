package firewall

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// defaultSSHConfig 是 sshd 主配置路径。
const defaultSSHConfig = "/etc/ssh/sshd_config"

// readSSHPort 只读解析 sshd_config 的 Port 指令。
// 返回首个有效 Port;无显式配置或解析失败返回默认 22。
// 仅读取展示——真正改 sshd 端口属危险联动,留给 security 模块,避免锁死。
func readSSHPort(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 22
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 || !strings.EqualFold(fields[0], "Port") {
			continue
		}
		if p, err := strconv.Atoi(fields[1]); err == nil && validPort(p) {
			return p
		}
	}
	return 22
}
