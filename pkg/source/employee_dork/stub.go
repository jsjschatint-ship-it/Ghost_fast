//go:build !broken_recovery
// +build !broken_recovery

// Code generated stub: original file is quarantined under build tag 'broken_recovery'
// due to cp936 encoding round-trip data loss. Repair the original then remove this stub.

package employee_dork

import (
	"context"
	"fmt"

	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

// EmployeeDork stub: returns ErrSourceQuarantined on every call.
type EmployeeDork struct{ *source.BaseSource }

// NewEmployeeDork constructs the stub.
func NewEmployeeDork() *EmployeeDork {
	return &EmployeeDork{BaseSource: source.NewBaseSource("employee_dork")}
}

// Accepts 接受的输入类型
func (s *EmployeeDork) Accepts() []string { return nil }

// Search returns an error indicating the source is quarantined.
func (s *EmployeeDork) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	return nil, fmt.Errorf("source %q is quarantined pending encoding repair", s.Name())
}
