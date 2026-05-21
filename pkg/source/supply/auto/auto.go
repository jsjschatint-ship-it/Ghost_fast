// Package auto 自动横向链：给一个目标 → 自动提取指纹 → 全部反查 → 标 supply-* 标签。
// 行为等同 plugins/supply/auto.py，是 pivots 的便利包装。
package auto

import (
	"github.com/wgpsec/ENScan/pkg/source"
	"github.com/wgpsec/ENScan/pkg/source/supply/pivots"
)

// Auto 数据源，复用 pivots 的全部逻辑，只改名字
type Auto struct {
	*pivots.Pivots
}

// New 创建
func New() *Auto {
	p := pivots.New()
	// 重命名为 supply_auto
	p.BaseSource = source.NewBaseSource("supply_auto")
	return &Auto{Pivots: p}
}
