package php

// Installer 抽象"安装新 PHP 版本"的能力,便于 mock 测试。真实实现可对接包管理器
// 或安装脚本;环境无对应能力时 Available 返回错误,模块据此回报不可用。
type Installer interface {
	// Available 报告安装能力是否就绪(供安装入口快速失败)。
	Available() error
	// Install 安装指定版本。version 已由调用方 ValidVersion 白名单校验。
	// 返回安装过程的合并输出。
	Install(version string) (string, error)
}

// unavailableInstaller 是默认实现:环境未提供安装后端,一律回报不可用。
type unavailableInstaller struct{}

// NewUnavailableInstaller 返回一个始终不可用的安装器(默认接线)。
func NewUnavailableInstaller() Installer { return unavailableInstaller{} }

func (unavailableInstaller) Available() error {
	return errInstallUnavailable
}

func (unavailableInstaller) Install(string) (string, error) {
	return "", errInstallUnavailable
}
