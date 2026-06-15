package appstore

import "fmt"

// Settings 是可配置的应用商店路径。持久化在 appstore_settings 表(单行)。
type Settings struct {
	AppsRoot   string `json:"apps_root"`   // 应用数据根目录,每个实例建子目录
	ProjectDir string `json:"project_dir"` // compose 项目文件目录(渲染的 compose.yml 落盘处)
}

// DefaultSettings 是首次运行的默认路径(对标 1Panel/aaPanel 习惯)。
func DefaultSettings() Settings {
	return Settings{
		AppsRoot:   "/opt/xpanel/apps",
		ProjectDir: "/opt/xpanel/apps/_projects",
	}
}

// validate 校验设置路径(绝对、无 ..、无元字符)。任一非法即拒绝写入。
func (s Settings) validate() error {
	if err := validAbsPath(s.AppsRoot); err != nil {
		return fmt.Errorf("apps_root: %w", err)
	}
	if err := validAbsPath(s.ProjectDir); err != nil {
		return fmt.Errorf("project_dir: %w", err)
	}
	return nil
}
