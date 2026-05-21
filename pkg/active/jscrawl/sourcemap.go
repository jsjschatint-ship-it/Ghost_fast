package jscrawl

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

// sourceMapV3 mirrors a Source Map v3 document. Fields we don't care about
// (mappings / sourceRoot / names) are intentionally elided.
type sourceMapV3 struct {
	Version        int      `json:"version"`
	File           string   `json:"file,omitempty"`
	Sources        []string `json:"sources,omitempty"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
}

// tryFetchSourceMap, given a JS URL, attempts to fetch <js>.map. If the
// response isn't a valid Source Map document we return nil quietly --
// most CDNs strip .map files in production, so 404 is the common case and
// shouldn't be considered an error.
//
// Returns:
//   - info: the parsed metadata (URL, sources[], etc.) iff parse succeeded.
//   - matches: secret/endpoint findings extracted from sourcesContent[]
//     concatenated -- folded into Result.Secrets at aggregation time.
func tryFetchSourceMap(ctx context.Context, client *http.Client, jsURL string, cfg *Config, rl *rateLimiter) (info *SourceMapInfo, matches []*Match) {
	mapURL := guessMapURL(jsURL)
	if mapURL == "" {
		return nil, nil
	}
	body, status, _, err := do(ctx, client, mapURL, cfg, rl)
	if err != nil || status != 200 || len(body) == 0 {
		return nil, nil
	}

	var doc sourceMapV3
	// Some servers send the map as text/plain with a BOM -- strip it before
	// JSON parsing. encoding/json is byte-order-mark-intolerant.
	body = stripBOM(body)
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, nil
	}
	info = &SourceMapInfo{
		URL:     mapURL,
		Version: doc.Version,
		File:    doc.File,
		Sources: doc.Sources,
	}
	if len(doc.SourcesContent) == 0 {
		return info, nil
	}
	info.HasContent = true
	// Run the secret/endpoint rule set over each sourcesContent entry.
	// Concatenating then scanning would lose attribution to filenames; we
	// scan per-entry so the eventual (aggregated) Match still has its
	// rule + value, and the BytesRecovered counter is accurate.
	for _, content := range doc.SourcesContent {
		if content == "" {
			continue
		}
		info.BytesRecovered += len(content)
		ms := scanBody(content)
		matches = append(matches, ms...)
	}
	info.SecretsInContent = countByType(matches, "secret")
	return info, matches
}

// guessMapURL returns "" if the .map URL would be invalid. Most JS files
// follow the convention `<jsURL>.map`. We strip any querystring before
// appending — querystrings on .map paths are usually cache-busting hashes
// that won't be honoured by the map server.
func guessMapURL(jsURL string) string {
	jsURL = strings.TrimSpace(jsURL)
	if jsURL == "" {
		return ""
	}
	// Only attempt for .js URLs (with optional ?query). Everything else
	// (HTML pages, .css) shouldn't trigger a .map fetch.
	cut := jsURL
	if i := strings.IndexAny(jsURL, "?#"); i >= 0 {
		cut = jsURL[:i]
	}
	if !strings.HasSuffix(strings.ToLower(cut), ".js") {
		return ""
	}
	return cut + ".map"
}

// stripBOM removes a UTF-8 BOM if present. JSON parsers are intolerant of
// BOMs and many edge servers happily emit one for "text/plain" .map files.
func stripBOM(b []byte) []byte {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:]
	}
	return b
}

// countByType returns how many Matches in the list have Type == kind.
func countByType(ms []*Match, kind string) int {
	n := 0
	for _, m := range ms {
		if m != nil && m.Type == kind {
			n++
		}
	}
	return n
}
