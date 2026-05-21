//go:build !broken_recovery
// +build !broken_recovery

// Code generated stub: original file is quarantined under build tag 'broken_recovery'
// due to cp936 encoding round-trip data loss. Repair the original then remove this stub.

package chaos

import (
	"context"
	"fmt"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// Chaos stub: returns ErrSourceQuarantined on every call.
type Chaos struct{ *source.BaseSource }

// NewChaos constructs the stub.
func NewChaos() *Chaos {
	return &Chaos{BaseSource: source.NewBaseSource("chaos")}
}

// Accepts 接受的输入类型
func (s *Chaos) Accepts() []string { return nil }

// Search returns an error indicating the source is quarantined.
func (s *Chaos) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	return nil, fmt.Errorf("source %q is quarantined pending encoding repair", s.Name())
}
