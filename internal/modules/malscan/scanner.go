package malscan

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ScanLimits 约束单次扫描的资源消耗,防 DoS。零值用 defaultLimits。
type ScanLimits struct {
	MaxFileSize  int64 // 超过此大小的文件跳过(字节)
	MaxFiles     int   // 最多扫描的文件数,达到即停止遍历
	ScoreToFlag  int   // 文件累计得分 >= 此值即标记为可疑
	MaxLineBytes int   // 单行最大字节,超长行(疑似压缩载荷)截断扫描该行
}

func defaultLimits() ScanLimits {
	return ScanLimits{
		MaxFileSize:  2 * 1024 * 1024, // 2 MiB
		MaxFiles:     50000,
		ScoreToFlag:  10,
		MaxLineBytes: 1 << 20, // 1 MiB
	}
}

// scanExts 是被扫描的脚本后缀(小写,含点)。其它后缀与无后缀文件跳过。
var scanExts = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".php5": true, ".phtml": true,
	".js": true, ".jsp": true, ".jspx": true,
	".asp": true, ".aspx": true, ".ashx": true,
	".py": true, ".pl": true, ".cgi": true, ".sh": true,
}

// Match 是文件内一条规则命中。Line 从 1 计;Excerpt 为脱敏后的命中行片段。
type Match struct {
	RuleID  string `json:"rule_id"`
	Rule    string `json:"rule"`
	Line    int    `json:"line"`
	Score   int    `json:"score"`
	Excerpt string `json:"excerpt"`
}

// FileResult 汇总单个文件的扫描结论。Suspicious 由 Score 与阈值决定。
type FileResult struct {
	Path       string  `json:"path"`
	Score      int     `json:"score"`
	Suspicious bool    `json:"suspicious"`
	Matches    []Match `json:"matches"`
}

// ScanReport 是一次目录扫描的汇总。
type ScanReport struct {
	Root         string       `json:"root"`
	FilesScanned int          `json:"files_scanned"`
	FilesSkipped int          `json:"files_skipped"`
	Flagged      []FileResult `json:"flagged"`
}

// scanTree 遍历 root 子树,按规则扫描脚本文件,返回命中可疑的文件。
// skip 返回 true 的绝对路径会被跳过(白名单)。root 必须是已存在的绝对路径。
// 只读:不修改任何文件,不跟随目录符号链接(避免遍历逃逸与软链环)。
func scanTree(root string, rules []Rule, lim ScanLimits, skip func(abs string) bool) (ScanReport, error) {
	if lim.MaxFileSize == 0 {
		lim = defaultLimits()
	}
	rep := ScanReport{Root: root}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // 单个条目读取失败(权限等)跳过,不中断整体扫描
		}
		if d.IsDir() {
			return nil
		}
		// 不跟随符号链接:软链目标可能在 root 外或形成环。
		if d.Type()&os.ModeSymlink != 0 {
			rep.FilesSkipped++
			return nil
		}
		if !scanExts[strings.ToLower(filepath.Ext(path))] {
			return nil
		}
		if skip != nil && skip(path) {
			rep.FilesSkipped++
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil || info.Size() > lim.MaxFileSize {
			rep.FilesSkipped++
			return nil
		}
		if rep.FilesScanned >= lim.MaxFiles {
			return filepath.SkipAll
		}
		res, scanned := scanFile(path, rules, lim)
		if !scanned {
			rep.FilesSkipped++
			return nil
		}
		rep.FilesScanned++
		if res.Suspicious {
			rep.Flagged = append(rep.Flagged, res)
		}
		return nil
	})
	if err != nil {
		return ScanReport{}, err
	}
	sort.Slice(rep.Flagged, func(i, j int) bool {
		return rep.Flagged[i].Score > rep.Flagged[j].Score
	})
	return rep, nil
}

// scanFile 读取并按规则扫描单文件。二进制文件跳过(scanned=false)。
func scanFile(path string, rules []Rule, lim ScanLimits) (FileResult, bool) {
	f, err := os.Open(path)
	if err != nil {
		return FileResult{}, false
	}
	defer f.Close()

	// 读头部判定是否二进制:含 NUL 字节即视为二进制,跳过。
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	if bytes.IndexByte(head[:n], 0) >= 0 {
		return FileResult{}, false
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return FileResult{}, false
	}

	res := FileResult{Path: path}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), lim.MaxLineBytes)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		for _, rule := range rules {
			if rule.re.MatchString(line) {
				res.Score += int(rule.Score)
				res.Matches = append(res.Matches, Match{
					RuleID:  rule.ID,
					Rule:    rule.Name,
					Line:    lineNo,
					Score:   int(rule.Score),
					Excerpt: excerpt(line),
				})
			}
		}
	}
	// scanner 出错(如超长行)不致命:已扫到的命中仍有效。
	res.Suspicious = res.Score >= lim.ScoreToFlag
	return res, true
}

// excerpt 截取并清理命中行,避免在 API/日志里回显超长载荷或控制字符。
func excerpt(line string) string {
	const max = 200
	line = strings.TrimSpace(line)
	if len(line) > max {
		line = line[:max] + "…"
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\t' {
			return ' '
		}
		return r
	}, line)
}
