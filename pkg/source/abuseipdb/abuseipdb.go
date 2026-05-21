package abuseipdb

import (
	"context"
	"fmt"
	"time"

	"github.com/imroc/req/v3"
	"github.com/tidwall/gjson"
	"github.com/wgpsec/ENScan/pkg/models"
	"github.com/wgpsec/ENScan/pkg/source"
)

type AbuseIPDB struct {
	*source.BaseSource
	client *req.Client
}

func NewAbuseIPDB() *AbuseIPDB {
	s := &AbuseIPDB{BaseSource: source.NewBaseSource("abuseipdb")}
	s.client = req.C().SetTimeout(30 * time.Second).SetUserAgent("Ghost/1.0")
	return s
}

func (s *AbuseIPDB) Name() string                       { return s.BaseSource.Name() }
func (s *AbuseIPDB) Accepts() []string                  { return []string{"ip"} }
func (s *AbuseIPDB) NeedsKey() bool                     { return true }
func (s *AbuseIPDB) SetKey(k string)                    { s.BaseSource.SetKey(k) }
func (s *AbuseIPDB) SetConfig(cfg map[string]any) error { return s.BaseSource.SetConfig(cfg) }

func (s *AbuseIPDB) Search(ctx context.Context, target string, opts ...source.SearchOption) ([]*models.Asset, error) {
	u := fmt.Sprintf("https://api.abuseipdb.com/api/v2/check?ipAddress=%s&maxAgeInDays=90", target)
	resp, err := s.client.R().SetContext(ctx).SetHeader("Key", s.BaseSource.Key()).SetHeader("Accept", "application/json").Get(u)
	if err != nil {
		return nil, fmt.Errorf("abuseipdb: %w", err)
	}
	d := gjson.Parse(resp.String()).Get("data")
	score := d.Get("abuseConfidenceScore").Int()
	if score == 0 {
		return nil, nil
	}
	a := models.NewAsset().WithTitle(fmt.Sprintf("[AbuseIPDB] %s (%d%%)", target, score)).
		WithIP(target).WithSource(s.Name()).WithTags("malicious", "abuseipdb").
		WithRaw("score", fmt.Sprintf("%d", score)).
		WithRaw("country", d.Get("countryCode").String()).
		WithRaw("isp", d.Get("isp").String())
	return []*models.Asset{a}, nil
}
