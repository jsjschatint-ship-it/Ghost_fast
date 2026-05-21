package jscrawl

import "regexp"

// rule pairs a regex with its category + label + severity.
type rule struct {
	Name     string
	Type     string // "endpoint" | "secret"
	Severity string // info|low|medium|high|critical
	Re       *regexp.Regexp
	// Group is the regex submatch index that holds the actual value to
	// surface; 0 means the whole match.
	Group int
	// MinLen filters obvious false positives where the captured value is too
	// short to be a real key/endpoint.
	MinLen int
}

// rules is the curated list of regex fingerprints. Order is irrelevant —
// every page is scanned with every rule. Patterns sourced from gitleaks /
// trufflehog / SecretFinder, hand-trimmed for false-positive rate.
//
// Endpoint regexes are intentionally narrow: we want absolute paths
// (`/api/...`) and full URLs, but NOT every short single-quoted string in a
// JS bundle (those are mostly i18n keys and CSS classes).
var rules = []rule{
	// ---------- Endpoints ----------
	{
		Name:     "absolute_url",
		Type:     "endpoint",
		Severity: "info",
		Re:       regexp.MustCompile(`https?://[a-zA-Z0-9_.\-]+(?::\d+)?(?:/[a-zA-Z0-9_.\-/?#=&%~+:]*)?`),
		MinLen:   12,
	},
	{
		Name:     "api_path",
		Type:     "endpoint",
		Severity: "info",
		// Captures /api/... /v1/... /graphql, etc., as quoted JS string.
		Re:     regexp.MustCompile(`["'](/(?:api|v\d|graphql|rest|internal|admin|auth|oauth|sso|user|users|account|portal|console|backend|service|services|gateway|public)(?:/[a-zA-Z0-9_.\-/?#=&%~+:]+)?)["']`),
		Group:  1,
		MinLen: 5,
	},

	// ---------- Cloud / IaaS keys ----------
	{
		Name:     "aws_access_key_id",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b`),
		MinLen:   20,
	},
	{
		Name:     "aws_secret_key",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`(?i)aws(?:.{0,20})?(?:secret|secret_access_key)["'\s:=]+([A-Za-z0-9/+=]{40})`),
		Group:    1,
		MinLen:   40,
	},
	{
		Name:     "aliyun_access_key",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\bLTAI[A-Za-z0-9]{16,20}\b`),
		MinLen:   20,
	},
	{
		Name:     "tencent_secret_id",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\bAKID[A-Za-z0-9]{32,40}\b`),
		MinLen:   36,
	},
	{
		Name:     "google_api_key",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
		MinLen:   39,
	},
	{
		Name:     "google_oauth_id",
		Type:     "secret",
		Severity: "low",
		Re:       regexp.MustCompile(`\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b`),
		MinLen:   60,
	},
	{
		Name:     "azure_storage_key",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`(?i)DefaultEndpointsProtocol=https;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{40,}`),
		MinLen:   60,
	},

	// ---------- Source-control / CI tokens ----------
	{
		Name:     "github_token",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,251}\b`),
		MinLen:   40,
	},
	{
		Name:     "gitlab_token",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{20,}\b`),
		MinLen:   26,
	},
	{
		Name:     "slack_token",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`),
		MinLen:   24,
	},
	{
		Name:     "slack_webhook",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9]{8,}/B[A-Za-z0-9]{8,}/[A-Za-z0-9]{20,}`),
		MinLen:   60,
	},
	{
		Name:     "bearer_token",
		Type:     "secret",
		Severity: "medium",
		// Looks for `Bearer <jwt-or-base64>` literals embedded as JS strings.
		Re:     regexp.MustCompile(`(?i)["']Bearer\s+([A-Za-z0-9_\-\.=]{20,})["']`),
		Group:  1,
		MinLen: 20,
	},
	{
		Name:     "jwt",
		Type:     "secret",
		Severity: "medium",
		// 3-segment base64url with header that contains "alg".
		Re:     regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{6,}\.eyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\b`),
		MinLen: 30,
	},
	{
		Name:     "stripe_live_key",
		Type:     "secret",
		Severity: "critical",
		Re:       regexp.MustCompile(`\bsk_live_[A-Za-z0-9]{24,}\b`),
		MinLen:   30,
	},
	{
		Name:     "stripe_publishable",
		Type:     "secret",
		Severity: "low",
		Re:       regexp.MustCompile(`\bpk_live_[A-Za-z0-9]{24,}\b`),
		MinLen:   30,
	},
	{
		Name:     "twilio_sid",
		Type:     "secret",
		Severity: "medium",
		Re:       regexp.MustCompile(`\bAC[a-z0-9]{32}\b`),
		MinLen:   34,
	},
	{
		Name:     "sendgrid_key",
		Type:     "secret",
		Severity: "high",
		Re:       regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`),
		MinLen:   65,
	},
	{
		Name:     "private_key_block",
		Type:     "secret",
		Severity: "critical",
		Re:       regexp.MustCompile(`-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----`),
		MinLen:   30,
	},
	{
		Name:     "generic_api_key",
		Type:     "secret",
		Severity: "low",
		// Conservative: requires a "key/secret/token" hint AND a long random-looking value.
		Re:     regexp.MustCompile(`(?i)(?:api[_-]?key|access[_-]?token|secret[_-]?key|auth[_-]?token)["'\s:=]+["']([A-Za-z0-9_\-]{24,})["']`),
		Group:  1,
		MinLen: 24,
	},
	{
		Name:     "source_map",
		Type:     "secret",
		Severity: "medium",
		// .map files leak the original source — surface them as findings.
		Re:     regexp.MustCompile(`//[#@]\s*sourceMappingURL=([^\s]+\.map)`),
		Group:  1,
		MinLen: 5,
	},
}

// jsURLPattern picks up every JS file URL in raw text — used to find chained
// imports inside JS bundles (webpack chunk hints, dynamic imports, etc.).
var jsURLPattern = regexp.MustCompile(`["']([^"'\s<>]+?\.js(?:\?[^"'\s<>]*)?)["']`)

// wsURLPattern catches ws:// and wss:// URLs in any body. We require at least
// host (no scheme-only); query/path optional. Used to surface real-time API
// endpoints (Socket.IO, GraphQL subscriptions, WebPush relays, ...).
var wsURLPattern = regexp.MustCompile(`(?i)\b(wss?://[a-zA-Z0-9_.\-]+(?::\d+)?(?:/[a-zA-Z0-9_.\-/?#=&%~+:]*)?)`)
