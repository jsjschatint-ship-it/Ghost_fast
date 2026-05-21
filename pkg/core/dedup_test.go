package core

import (
	"testing"

	"github.com/wgpsec/ENScan/pkg/models"
)

func TestDedupMergeInitializesRawMap(t *testing.T) {
	assets := []*models.Asset{
		models.NewAsset().WithHost("example.com").WithSource("a"),
		models.NewAsset().WithHost("example.com").WithSource("b").WithRaw("k", "v"),
	}

	out, stats := DedupWithStats(assets, KeySmart)
	if len(out) != 1 {
		t.Fatalf("expected 1 deduped asset, got %d", len(out))
	}
	if stats.MergedGroups != 1 {
		t.Fatalf("expected 1 merged group, got %d", stats.MergedGroups)
	}
	if out[0].Raw == nil || out[0].Raw["k"] != "v" {
		t.Fatalf("expected merged raw k=v, got %#v", out[0].Raw)
	}
}
