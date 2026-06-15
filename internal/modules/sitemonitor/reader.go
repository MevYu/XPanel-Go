package sitemonitor

import (
	"bufio"
	"os"

	"github.com/MevYu/XPanel-Go/internal/system"
)

// LogReader 抽象日志来源,便于测试注入样本日志而不依赖真实文件。
// path 已由调用方经 SafeJoin 限定在 LogRoot 内。maxLines>0 时只返回末尾这么多行。
type LogReader interface {
	// TailLines 返回 path 文件末尾最多 maxLines 行(按出现顺序)。
	TailLines(path string, maxLines int) ([]string, error)
}

// FileLogReader 是基于本地文件的只读 LogReader:只读分析,绝不改系统。
type FileLogReader struct{}

// TailLines 流式扫描整个文件,用环形缓冲只保留末尾 maxLines 行,内存上限为 maxLines。
// 不一次性把整个文件读进内存,适配大日志。
func (FileLogReader) TailLines(path string, maxLines int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if maxLines <= 0 {
		maxLines = DefaultMaxLines
	}
	ring := make([]string, 0, min(maxLines, 4096))
	count := 0

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if len(ring) < maxLines {
			ring = append(ring, line)
		} else {
			ring[count%maxLines] = line
		}
		count++
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	// 满载时环形缓冲需按写入顺序重排。
	if count > maxLines {
		start := count % maxLines
		out := make([]string, 0, maxLines)
		out = append(out, ring[start:]...)
		out = append(out, ring[:start]...)
		return out, nil
	}
	return ring, nil
}

// resolveLogPath 把请求的日志路径限定在 LogRoot 子树内,挡路径穿越与符号链接逃逸。
// rel 为空时回落到 Settings.AccessLog。
func resolveLogPath(s Settings, rel string) (string, error) {
	target := rel
	if target == "" {
		target = s.AccessLog
	}
	return system.SafeJoin(s.LogRoot, target)
}
