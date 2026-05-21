//go:build !broken_recovery
// +build !broken_recovery

// Code generated stub: original file is quarantined under build tag 'broken_recovery'
// due to cp936 encoding round-trip data loss. Repair the original then remove this stub.

package source_map_leak

import (
	"context"
	"fmt"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// SourceMapLeak 实现 JS Source Map 泄露检测
type SourceMapLeak struct{ *source.BaseSource }

// NewSourceMapLeak constructs the stub.
func NewSourceMapLeak() *SourceMapLeak {
	return &SourceMapLeak{BaseSource: source.NewBaseSource("source_map_leak")}
}

// Accepts 接受的输入类型
func (s *SourceMapLeak) Accepts() []string { return nil }

// Search returns an error indicating the source is quarantined.
func (s *SourceMapLeak) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	return nil, fmt.Errorf("source %q is quarantined pending encoding repair", s.Name())
}
