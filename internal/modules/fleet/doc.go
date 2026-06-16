// Package fleet 是 build-tag 门控的多机集中管理模块。
//
// 实际实现全部位于 //go:build fleet 文件中,默认构建下本包为空,
// 既不编入任何 fleet 逻辑也不引入 NATS 依赖。本文件仅提供包声明,
// 使默认构建下该目录仍是一个合法(空)包,便于 `go test ./...` 通过。
package fleet
