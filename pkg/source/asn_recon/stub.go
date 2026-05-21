//go:build !broken_recovery
// +build !broken_recovery

// Code generated stub: original file is quarantined under build tag 'broken_recovery'
// due to cp936 encoding round-trip data loss. Repair the original then remove this stub.

package asn_recon

import (
	"context"
	"fmt"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// ASNRecon stub: returns ErrSourceQuarantined on every call.
type ASNRecon struct{ *source.BaseSource }

// NewASNRecon constructs the stub.
func NewASNRecon() *ASNRecon {
	return &ASNRecon{BaseSource: source.NewBaseSource("asn_recon")}
}

// Accepts 接受的输入类型
func (s *ASNRecon) Accepts() []string { return nil }

// Search returns an error indicating the source is quarantined.
func (s *ASNRecon) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	return nil, fmt.Errorf("source %q is quarantined pending encoding repair", s.Name())
}
