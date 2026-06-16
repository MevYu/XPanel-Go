package php

import (
	"os"
	"strings"
)

// maxLogTail 是日志 tail 读取的字节上限,只读文件尾部,挡掉超大日志全量读入。
const maxLogTail = 256 << 10 // 256 KiB

// tailLines 返回 content 末尾最多 n 行(保持原顺序)。n <= 0 时返回空串。
func tailLines(content string, n int) string {
	if n <= 0 {
		return ""
	}
	content = strings.TrimRight(content, "\n")
	if content == "" {
		return ""
	}
	lines := strings.Split(content, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// readLogTail 读取日志文件尾部(至多 maxLogTail 字节)的最后 n 行。
// 文件不存在返回空串与 false(调用方据此回 404)。
func readLogTail(path string, n int) (string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", false
	}
	size := info.Size()
	var offset int64
	if size > maxLogTail {
		offset = size - maxLogTail
	}
	if _, err := f.Seek(offset, 0); err != nil {
		return "", false
	}
	buf := make([]byte, size-offset)
	read, _ := f.Read(buf)
	return tailLines(string(buf[:read]), n), true
}
