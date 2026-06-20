package cron

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// runResult 是一次任务执行的结果。Output 为合并的 stdout+stderr(已截断)。
type runResult struct {
	StartedAt  int64  // unix 秒
	DurationMs int64  // 执行耗时
	ExitCode   int    // 进程退出码;-1 表示未能启动
	Output     string // 合并输出,截断到 maxOutputBytes
	Err        string // 启动/系统层错误(非进程退出码),空表示无
}

// maxOutputBytes 限制单次执行记录的输出大小,防日志膨胀。
const maxOutputBytes = 16 * 1024

// runner 抽象任务执行,便于用 mock 测试调度与记录逻辑。
type runner interface {
	run(ctx context.Context, j Job) runResult
}

// execRunner 是真实执行器:按任务类型构造命令(始终参数数组,绝不拼 shell 串),
// 捕获输出与退出码。logCutRoot 限定 log_cut 路径;scriptDir 存放 shell 脚本。
// backupSite/backupDB 是进程内备份钩子(由宿主经 SetBackupHooks 注入);nil 表示未接通。
type execRunner struct {
	logCutRoot string
	scriptDir  string
	backupSite func(target string) error // backup_site 钩子;target 为站点名
	backupDB   func(target string) error // backup_db 钩子;target 为 "<engine>:<database>"
}

func (e *execRunner) run(ctx context.Context, j Job) runResult {
	// 备份任务不是外部命令,走进程内钩子:捕获错误成 runResult,与命令路径的成功/失败语义一致。
	if j.Type == taskBackupSite || j.Type == taskBackupDB {
		return e.runBackup(j)
	}

	start := time.Now()
	res := runResult{StartedAt: start.Unix(), ExitCode: -1}

	cmd, cleanup, err := e.build(ctx, j)
	if cleanup != nil {
		defer cleanup()
	}
	if err != nil {
		res.Err = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	var buf cappedBuffer
	buf.limit = maxOutputBytes
	cmd.Stdout = &buf
	cmd.Stderr = &buf

	runErr := cmd.Run()
	res.DurationMs = time.Since(start).Milliseconds()
	res.Output = buf.String()

	switch {
	case runErr == nil:
		res.ExitCode = 0
	default:
		var ee *exec.ExitError
		if errors.As(runErr, &ee) {
			res.ExitCode = ee.ExitCode()
		} else {
			res.Err = runErr.Error()
		}
	}
	return res
}

// build 把 Job 编译成可执行的 *exec.Cmd。cleanup 删除临时脚本文件(可为 nil)。
func (e *execRunner) build(ctx context.Context, j Job) (*exec.Cmd, func(), error) {
	switch j.Type {
	case taskCommand:
		// crontab 本就用 /bin/sh 跑命令行;此处复刻该语义。命令已过注入校验。
		return exec.CommandContext(ctx, "sh", "-c", j.Payload.Command), nil, nil

	case taskShell:
		path, cleanup, err := e.writeScript(j.ID, j.Payload.Script)
		if err != nil {
			return nil, nil, err
		}
		return exec.CommandContext(ctx, "sh", path), cleanup, nil

	case taskReleaseMem:
		// sync 后 drop_caches。无用户输入。
		return exec.CommandContext(ctx, "sh", "-c", "sync && echo 3 > /proc/sys/vm/drop_caches"), nil, nil

	case taskLogCut:
		abs, err := system.SafeJoin(e.logCutRoot, j.Payload.Path)
		if err != nil {
			return nil, nil, fmt.Errorf("log_cut path: %w", err)
		}
		return exec.CommandContext(ctx, "truncate", "-s", "0", abs), nil, nil

	case taskURL:
		to := strconv.Itoa(j.Payload.Timeout)
		// -f 失败返回非 0,-sS 静默但显示错误,--max-time 限时。
		return exec.CommandContext(ctx, "curl", "-fsS", "--max-time", to, j.Payload.URL), nil, nil

	}
	return nil, nil, fmt.Errorf("unknown task type %q", j.Type)
}

// runBackup 执行进程内备份钩子,把成功/失败映射到 runResult(退出码 0/1)。
// 钩子未注入(nil)时报明确错误而非静默成功。
func (e *execRunner) runBackup(j Job) runResult {
	start := time.Now()
	res := runResult{StartedAt: start.Unix(), ExitCode: -1}

	var hook func(string) error
	switch j.Type {
	case taskBackupSite:
		hook = e.backupSite
	case taskBackupDB:
		hook = e.backupDB
	}
	if hook == nil {
		res.Err = fmt.Sprintf("%s backup hook not wired (target=%s)", j.Type, j.Payload.Target)
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	err := hook(j.Payload.Target)
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		res.ExitCode = 1
		res.Output = err.Error()
		return res
	}
	res.ExitCode = 0
	res.Output = "backup ok: " + j.Payload.Target
	return res
}

// writeScript 把脚本内容写到 scriptDir 下的临时文件,返回路径与清理函数。
func (e *execRunner) writeScript(id int64, script string) (string, func(), error) {
	if err := os.MkdirAll(e.scriptDir, 0o700); err != nil {
		return "", nil, err
	}
	path := filepath.Join(e.scriptDir, fmt.Sprintf("job-%d.sh", id))
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		return "", nil, err
	}
	return path, func() { _ = os.Remove(path) }, nil
}

// cappedBuffer 是带上限的 bytes.Buffer:超出 limit 后丢弃多余写入,标记截断。
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len() >= c.limit {
		c.truncated = true
		return len(p), nil // 假装写入,避免上游报 short write
	}
	room := c.limit - c.buf.Len()
	if len(p) > room {
		c.buf.Write(p[:room])
		c.truncated = true
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) String() string {
	if c.truncated {
		return c.buf.String() + "\n...[output truncated]"
	}
	return c.buf.String()
}
