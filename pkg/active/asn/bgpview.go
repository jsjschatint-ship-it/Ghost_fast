package asn

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// bgpviewClient wraps the bgpview.io JSON API. All endpoints share a common
// envelope: `{"status":"ok","data":{...}}`.
type bgpviewClient struct {
	base   string
	client *http.Client
	ua     string
}

func newBGPViewClient(base, ua string, client *http.Client) *bgpviewClient {
	return &bgpviewClient{base: base, client: client, ua: ua}
}

// ipResp models /ip/<ip>.
type ipResp struct {
	Status string `json:"status"`
	Data   struct {
		IP       string `json:"ip"`
		Prefixes []struct {
			Prefix    string `json:"prefix"`
			IPVersion int    `json:"ip_version"` // some routes return string; tolerate via custom
			ASN       struct {
				ASN         int    `json:"asn"`
				Name        string `json:"name"`
				Description string `json:"description"`
				CountryCode string `json:"country_code"`
			} `json:"asn"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"prefixes"`
	} `json:"data"`
}

// asnPrefixesResp models /asn/<num>/prefixes.
type asnPrefixesResp struct {
	Status string `json:"status"`
	Data   struct {
		IPv4 []struct {
			Prefix      string `json:"prefix"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"ipv4_prefixes"`
		IPv6 []struct {
			Prefix      string `json:"prefix"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"ipv6_prefixes"`
	} `json:"data"`
}

// asnDetailResp models /asn/<num>.
type asnDetailResp struct {
	Status string `json:"status"`
	Data   struct {
		ASN              int      `json:"asn"`
		Name             string   `json:"name"`
		DescriptionShort string   `json:"description_short"`
		DescriptionFull  []string `json:"description_full"`
		CountryCode      string   `json:"country_code"`
	} `json:"data"`
}

// searchResp models /search?query_term=<org>.
type searchResp struct {
	Status string `json:"status"`
	Data   struct {
		ASNs []struct {
			ASN         int    `json:"asn"`
			Name        string `json:"name"`
			Description string `json:"description"`
			CountryCode string `json:"country_code"`
		} `json:"asns"`
	} `json:"data"`
}

// fetchJSON GETs `path`, decodes JSON into v.
func (b *bgpviewClient) fetchJSON(ctx context.Context, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, b.base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", b.ua)
	resp, err := b.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("bgpview: HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 20*1024*1024))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// ipToASNs returns one IPMapping + the ASN ints for one IP.
func (b *bgpviewClient) ipToASNs(ctx context.Context, ip string) (*IPMapping, []int, error) {
	var r ipResp
	if err := b.fetchJSON(ctx, "/ip/"+ip, &r); err != nil {
		return nil, nil, err
	}
	if len(r.Data.Prefixes) == 0 {
		return &IPMapping{IP: ip, Source: "bgpview", Err: "no prefix announced"}, nil, nil
	}
	asn := r.Data.Prefixes[0].ASN.ASN
	prefix := r.Data.Prefixes[0].Prefix
	asns := make([]int, 0, len(r.Data.Prefixes))
	seen := map[int]struct{}{}
	for _, p := range r.Data.Prefixes {
		if p.ASN.ASN == 0 {
			continue
		}
		if _, ok := seen[p.ASN.ASN]; ok {
			continue
		}
		seen[p.ASN.ASN] = struct{}{}
		asns = append(asns, p.ASN.ASN)
	}
	return &IPMapping{IP: ip, ASN: asn, Prefix: prefix, Source: "bgpview"}, asns, nil
}

// asnPrefixes returns all announced prefixes (v4 + v6) for one ASN.
func (b *bgpviewClient) asnPrefixes(ctx context.Context, num int, includeV6 bool, cap int) ([]*Prefix, error) {
	var r asnPrefixesResp
	if err := b.fetchJSON(ctx, fmt.Sprintf("/asn/%d/prefixes", num), &r); err != nil {
		return nil, err
	}
	var out []*Prefix
	for _, p := range r.Data.IPv4 {
		out = append(out, &Prefix{CIDR: p.Prefix, Family: 4, Name: p.Name, Description: p.Description, Country: p.CountryCode})
		if cap > 0 && len(out) >= cap {
			return out, nil
		}
	}
	if includeV6 {
		for _, p := range r.Data.IPv6 {
			out = append(out, &Prefix{CIDR: p.Prefix, Family: 6, Name: p.Name, Description: p.Description, Country: p.CountryCode})
			if cap > 0 && len(out) >= cap {
				return out, nil
			}
		}
	}
	return out, nil
}

// asnDetail enriches an ASN with name + description.
func (b *bgpviewClient) asnDetail(ctx context.Context, num int) (*ASNInfo, error) {
	var r asnDetailResp
	if err := b.fetchJSON(ctx, fmt.Sprintf("/asn/%d", num), &r); err != nil {
		return nil, err
	}
	desc := r.Data.DescriptionShort
	if desc == "" && len(r.Data.DescriptionFull) > 0 {
		desc = r.Data.DescriptionFull[0]
	}
	return &ASNInfo{ASN: r.Data.ASN, Name: r.Data.Name, Description: desc, Country: r.Data.CountryCode}, nil
}

// searchOrg searches the bgpview.io DB for ASNs containing the term.
func (b *bgpviewClient) searchOrg(ctx context.Context, term string) ([]int, error) {
	var r searchResp
	if err := b.fetchJSON(ctx, "/search?query_term="+term, &r); err != nil {
		return nil, err
	}
	out := make([]int, 0, len(r.Data.ASNs))
	for _, a := range r.Data.ASNs {
		out = append(out, a.ASN)
	}
	return out, nil
}
