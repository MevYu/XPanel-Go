package system

import (
	"os"
	"os/exec"

	"github.com/creack/pty"
)

// PTYSession 是一个跑在伪终端里的 shell 进程。Pty 是主端,读写即与 shell 交互。
type PTYSession struct {
	Pty *os.File
	cmd *exec.Cmd
}

// StartPTY 在伪终端里起一个登录 shell。优先用 $SHELL,缺省 /bin/bash。
// 进程继承当前用户权限(由宿主进程决定),不提权。
func StartPTY() (*PTYSession, error) {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	cmd := exec.Command(shell)
	cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	f, err := pty.Start(cmd)
	if err != nil {
		return nil, err
	}
	return &PTYSession{Pty: f, cmd: cmd}, nil
}

// Resize 把伪终端窗口尺寸设为 rows×cols。非法尺寸(0)由 pty 层兜底忽略。
func (s *PTYSession) Resize(rows, cols uint16) error {
	return pty.Setsize(s.Pty, &pty.Winsize{Rows: rows, Cols: cols})
}

// Close 杀掉 shell 进程并关闭伪终端,回收资源。可重复调用。
func (s *PTYSession) Close() {
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
	_ = s.Pty.Close()
}

// ShellAvailable 供模块 HealthCheck 用:能否定位到可执行的 shell。
func ShellAvailable() error {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	_, err := exec.LookPath(shell)
	return err
}
