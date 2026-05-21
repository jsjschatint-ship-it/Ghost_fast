package tlscert

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

// crtShRaw is one row of crt.sh's `?output=json` response. Fields kept here
// are a strict subset of what's emitted — extras are tolerated by encoding/json.
type crtShRaw struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"` // newline-separated SAN list
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

// queryCrtSh queries crt.sh for `domain` and returns a normalised CTQuery.
// Uses identity= (full match) by default; callers can pre-prefix with "%."
// for wildcard subdomain coverage if desired (we do that in the runner).
func queryCrtSh(ctx context.Context, client *http.Client, domain string, maxRows int, ua string) *CTQuery {
	t0 := time.Now()
	q := &CTQuery{Domain: domain}
	// %25 = '%' URL-encoded — crt.sh uses it as wildcard.
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		q.Err = err.Error()
		q.DurationMS = time.Since(t0).Milliseconds()
		return q
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		q.Err = "fetch: " + err.Error()
		q.DurationMS = time.Since(t0).Milliseconds()
		return q
	}
	defer resp.Body.Close()
	q.HTTPStatus = resp.StatusCode
	if resp.StatusCode != 200 {
		// crt.sh sometimes returns 502/504 under load — surface the status
		// instead of trying to parse HTML error pages.
		q.Err = fmt.Sprintf("http %d", resp.StatusCode)
		q.DurationMS = time.Since(t0).Milliseconds()
		return q
	}

	// Body can be tens of MB for popular orgs — cap it.
	const maxBody = 50 * 1024 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		q.Err = "read: " + err.Error()
		q.DurationMS = time.Since(t0).Milliseconds()
		return q
	}

	var raw []crtShRaw
	if err := json.Unmarshal(body, &raw); err != nil {
		q.Err = "json: " + err.Error()
		q.DurationMS = time.Since(t0).Milliseconds()
		return q
	}

	if len(raw) > maxRows {
		raw = raw[:maxRows]
		q.Truncated = true
	}

	uniq := map[string]struct{}{}
	rows := make([]*CTRow, 0, len(raw))
	for _, r := range raw {
		row := &CTRow{
			IssuerCAID: r.IssuerCAID,
			IssuerName: r.IssuerName,
			CommonName: r.CommonName,
			NotBefore:  r.NotBefore,
			NotAfter:   r.NotAfter,
			EntryTime:  r.EntryTimestamp,
			SerialHex:  r.SerialNumber,
		}
		// crt.sh `name_value` is newline-separated; explode + dedup.
		if r.NameValue != "" {
			for _, n := range strings.Split(r.NameValue, "\n") {
				n = strings.TrimSpace(strings.ToLower(n))
				if n == "" {
					continue
				}
				row.NameValues = append(row.NameValues, n)
				uniq[n] = struct{}{}
			}
		}
		if r.CommonName != "" {
			cn := strings.ToLower(strings.TrimSpace(r.CommonName))
			uniq[cn] = struct{}{}
		}
		rows = append(rows, row)
	}
	q.Rows = rows
	q.UniqueNames = make([]string, 0, len(uniq))
	for k := range uniq {
		q.UniqueNames = append(q.UniqueNames, k)
	}
	sort.Strings(q.UniqueNames)
	q.DurationMS = time.Since(t0).Milliseconds()
	return q
}
