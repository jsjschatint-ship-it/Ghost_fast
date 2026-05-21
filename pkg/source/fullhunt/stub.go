//go:build !broken_recovery
// +build !broken_recovery

// Code generated stub: original file is quarantined under build tag 'broken_recovery'
// due to cp936 encoding round-trip data loss. Repair the original then remove this stub.

package fullhunt

import (
	"context"
	"fmt"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// FullHunt stub: returns ErrSourceQuarantined on every call.
type FullHunt struct{ *source.BaseSource }

// NewFullHunt constructs the stub.
func NewFullHunt() *FullHunt {
	return &FullHunt{BaseSource: source.NewBaseSource("fullhunt")}
}

// Accepts 接受的输入类型
func (s *FullHunt) Accepts() []string { return nil }

// Search returns an error indicating the source is quarantined.
func (s *FullHunt) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	return nil, fmt.Errorf("source %q is quarantined pending encoding repair", s.Name())
}
