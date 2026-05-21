//go:build !broken_recovery
// +build !broken_recovery

// Code generated stub: original file is quarantined under build tag 'broken_recovery'
// due to cp936 encoding round-trip data loss. Repair the original then remove this stub.

package company_structure_api

import (
	"context"
	"fmt"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// CompanyStructureAPI stub: returns ErrSourceQuarantined on every call.
type CompanyStructureAPI struct{ *source.BaseSource }

// NewCompanyStructureAPI constructs the stub.
func NewCompanyStructureAPI() *CompanyStructureAPI {
	return &CompanyStructureAPI{BaseSource: source.NewBaseSource("company_structure_api")}
}

// Accepts 接受的输入类型
func (s *CompanyStructureAPI) Accepts() []string { return nil }

// Search returns an error indicating the source is quarantined.
func (s *CompanyStructureAPI) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	return nil, fmt.Errorf("source %q is quarantined pending encoding repair", s.Name())
}
