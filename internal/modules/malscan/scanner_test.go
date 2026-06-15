package malscan

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSample 在 dir 下写一个样本文件,返回绝对路径。
func writeSample(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestScanFlagsOnelinerWebshell(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, "shell.php", "<?php @eval($_POST['cmd']); ?>")

	rep, err := scanTree(dir, builtinRules, defaultLimits(), nil)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(rep.Flagged) != 1 {
		t.Fatalf("want 1 flagged, got %d (%+v)", len(rep.Flagged), rep.Flagged)
	}
	fr := rep.Flagged[0]
	if !fr.Suspicious || fr.Score < int(SevCritical) {
		t.Errorf("oneliner should be high-score suspicious, got score=%d", fr.Score)
	}
	var hasOneliner bool
	for _, mt := range fr.Matches {
		if mt.RuleID == "oneliner_eval_request" {
			hasOneliner = true
		}
	}
	if !hasOneliner {
		t.Errorf("oneliner rule not matched: %+v", fr.Matches)
	}
}

func TestScanFlagsObfuscatedLoader(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, "loader.php", "<?php eval(gzinflate(base64_decode('abc'))); ?>")
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), nil)
	if len(rep.Flagged) != 1 {
		t.Fatalf("obfuscated loader should be flagged, got %d", len(rep.Flagged))
	}
}

func TestScanFlagsAspWebshell(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, "x.asp", `<% eval(request("c")) %>`)
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), nil)
	if len(rep.Flagged) != 1 {
		t.Fatalf("asp webshell should be flagged, got %d", len(rep.Flagged))
	}
}

func TestScanDoesNotFlagBenignFile(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, "index.php",
		"<?php\n$name = $_GET['name'];\necho 'Hello, ' . htmlspecialchars($name);\n")
	writeSample(t, dir, "util.js", "function add(a, b) { return a + b; }\n")
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), nil)
	if len(rep.Flagged) != 0 {
		t.Errorf("benign files must not be flagged, got %+v", rep.Flagged)
	}
}

func TestScanSkipsNonScriptExtensions(t *testing.T) {
	dir := t.TempDir()
	// 同样的恶意内容放在 .txt 里应被跳过(不在扫描后缀)。
	writeSample(t, dir, "note.txt", "<?php @eval($_POST['cmd']); ?>")
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), nil)
	if len(rep.Flagged) != 0 {
		t.Errorf(".txt should be skipped, got %+v", rep.Flagged)
	}
	if rep.FilesScanned != 0 {
		t.Errorf("no script files to scan, got FilesScanned=%d", rep.FilesScanned)
	}
}

func TestScanSkipsBinary(t *testing.T) {
	dir := t.TempDir()
	// .php 后缀但含 NUL 字节 -> 二进制,跳过。
	writeSample(t, dir, "blob.php", "GIF89a\x00\x00\x00@eval($_POST[x])")
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), nil)
	if len(rep.Flagged) != 0 {
		t.Errorf("binary file must be skipped, got %+v", rep.Flagged)
	}
}

func TestScanSkipsOversizeFile(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, "big.php", "<?php @eval($_POST['cmd']); ?>\n"+strings.Repeat("x", 4096))
	lim := defaultLimits()
	lim.MaxFileSize = 100 // 小于样本
	rep, _ := scanTree(dir, builtinRules, lim, nil)
	if rep.FilesScanned != 0 || len(rep.Flagged) != 0 {
		t.Errorf("oversize file must be skipped, scanned=%d flagged=%d", rep.FilesScanned, len(rep.Flagged))
	}
	if rep.FilesSkipped == 0 {
		t.Errorf("oversize file should count as skipped")
	}
}

func TestScanRespectsWhitelist(t *testing.T) {
	dir := t.TempDir()
	bad := writeSample(t, dir, "shell.php", "<?php @eval($_POST['cmd']); ?>")
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), func(abs string) bool { return abs == bad })
	if len(rep.Flagged) != 0 {
		t.Errorf("whitelisted file must not be flagged, got %+v", rep.Flagged)
	}
}

func TestScanReportsLineNumbers(t *testing.T) {
	dir := t.TempDir()
	writeSample(t, dir, "shell.php", "<?php\n\n@eval($_POST['cmd']);\n")
	rep, _ := scanTree(dir, builtinRules, defaultLimits(), nil)
	if len(rep.Flagged) != 1 {
		t.Fatalf("want 1 flagged")
	}
	var found bool
	for _, mt := range rep.Flagged[0].Matches {
		if mt.RuleID == "oneliner_eval_request" && mt.Line == 3 {
			found = true
		}
	}
	if !found {
		t.Errorf("expected oneliner match on line 3, got %+v", rep.Flagged[0].Matches)
	}
}
