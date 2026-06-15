package waf

import (
	"fmt"
	"os"
	"path/filepath"
)

// applier 负责把规则集落盘成 nginx 配置并安全地 reload。
// 流程:生成两段配置 → 原子写入 ConfigDir → nginx -t 整体校验 → 通过才 reload;
// 任一步失败回滚到旧文件,绝不留下会让 nginx -t 失败的配置。
type applier struct {
	ng Nginx
}

// apply 把 rs 渲染并应用到 set 指向的文件,经 nginx -t 把关后 reload。
// 返回 nginx 命令输出(供审计/排障)。任何校验失败都在写盘/exec 前拦截。
func (a applier) apply(set Settings, rs RuleSet) (string, error) {
	if err := set.Validate(); err != nil {
		return "", err
	}
	cfg, err := GenerateConfig(rs)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(set.ConfigDir, 0o755); err != nil {
		return "", fmt.Errorf("waf: create config dir: %w", err)
	}

	httpPath := set.httpConfPath()
	srvPath := set.serverConfPath()

	// 先备份旧内容用于回滚(文件可能尚不存在)。
	httpOld, httpExisted := readIfExists(httpPath)
	srvOld, srvExisted := readIfExists(srvPath)

	if err := writeAtomic(httpPath, cfg.HTTP); err != nil {
		return "", err
	}
	if err := writeAtomic(srvPath, cfg.Server); err != nil {
		restore(httpPath, httpOld, httpExisted)
		return "", err
	}

	// nginx -t 整体校验:新 include 不能破坏主配置,否则回滚。
	out, err := a.ng.Test(set.NginxConf)
	if err != nil {
		restore(httpPath, httpOld, httpExisted)
		restore(srvPath, srvOld, srvExisted)
		return out, fmt.Errorf("waf: nginx config test failed, rolled back: %w", err)
	}

	reloadOut, err := a.ng.Reload()
	if err != nil {
		// reload 失败不回滚文件:配置本身已通过 -t,问题在运行态,留下配置便于排障。
		return out + "\n" + reloadOut, fmt.Errorf("waf: nginx reload failed: %w", err)
	}
	return out + "\n" + reloadOut, nil
}

// readIfExists 读文件;不存在返回 ("", false)。其它错误当作不存在处理(写时会暴露)。
func readIfExists(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(b), true
}

// writeAtomic 原子写文件:写临时文件再 rename,避免 nginx 读到半截配置。
func writeAtomic(path, content string) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".waf-*.tmp")
	if err != nil {
		return fmt.Errorf("waf: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.WriteString(content); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("waf: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("waf: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("waf: rename config file: %w", err)
	}
	return nil
}

// restore 把文件回滚到旧内容;旧文件原本不存在则删除。回滚自身出错只能记录(调用方已在失败路径)。
func restore(path, old string, existed bool) {
	if existed {
		_ = writeAtomic(path, old)
		return
	}
	_ = os.Remove(path)
}
