package system

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// CrontabLockTimeout 限定获取 host crontab 互斥锁的最长等待:超时即放弃本次写,
// 宁可 sync 失败也不冒同机多实例「读-改-写」丢更新的风险。
var CrontabLockTimeout = 8 * time.Second

// CrontabLockPath 返回守护 host crontab 读-改-写的 advisory 锁文件路径。
// 同机管理同一用户 crontab 的所有实例必须解析到同一路径,flock 才能真正互斥,
// 故仅按 uid 命名、不按实例 key 区分。测试可覆盖本变量指向临时文件。
var CrontabLockPath = defaultCrontabLockPath

// defaultCrontabLockPath 按当前进程 uid 命名锁文件;优先 /run,不可写时回退 /tmp。
// flock 是 advisory 锁,文件内容无意义,只借其 inode 在进程间协调。
func defaultCrontabLockPath() string {
	name := fmt.Sprintf("xpanel-crontab-%d.lock", os.Getuid())
	runPath := filepath.Join("/run", name)
	if f, err := os.OpenFile(runPath, os.O_RDWR|os.O_CREATE, 0o600); err == nil {
		f.Close()
		return runPath
	}
	return filepath.Join("/tmp", name)
}

// LockCrontab 获取守护 host crontab「读-改-写」的进程间独占 advisory 锁
// (flock LOCK_EX),最多轮询等待 CrontabLockTimeout。返回的 release 关闭 fd——
// 这同时释放 flock(进程退出/fd 关闭时内核自动释放,无 stale 锁),调用方必须 defer。
// 超时或出错时不持有任何锁,调用方据此放弃写。
func LockCrontab() (release func(), err error) {
	path := CrontabLockPath()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open crontab lock %s: %w", path, err)
	}
	deadline := time.Now().Add(CrontabLockTimeout)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() { f.Close() }, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("flock crontab lock %s: %w", path, err)
		}
		if !time.Now().Before(deadline) {
			f.Close()
			return nil, fmt.Errorf("crontab lock %s busy after %s", path, CrontabLockTimeout)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
