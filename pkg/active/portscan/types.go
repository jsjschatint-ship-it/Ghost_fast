// Package portscan provides a TCP-connect port scanner with banner grabbing,
// nmap top-N port presets, per-host concurrency limiting and adaptive retries.
//
// Design choices:
//   - TCP connect scan only. SYN scans require raw sockets / Npcap on Windows,
//     and our priority is portability + working in restricted environments.
//   - Per-host concurrency cap: each target IP/host is limited to a maximum of
//     N simultaneous open connections to avoid tripping SYN-flood mitigations
//     that would otherwise cause every subsequent port to RST.
//   - Adaptive retries: a first-pass timeout (short, 1s) is followed by up to
//     RetryPerPort retries with a longer timeout (3s) — same heuristic nmap
//     uses as `--max-retries 2`.
//   - Banner grab: optional. When enabled, the scanner reads up to 256 bytes
//     for a brief window after connect; many services (SSH, FTP, SMTP, MySQL,
//     Redis MOTD-on-AUTH) volunteer a banner immediately, others stay silent.
package portscan

import (
	"time"

	"github.com/wgpsec/ENScan/pkg/models"
)

// Config tunes a port-scan run. The zero value gets sane defaults via Normalize.
type Config struct {
	// Ports is the explicit list of TCP port numbers to scan. If empty,
	// PortPreset / PortRange are consulted. The list will be deduped + sorted.
	Ports []int `json:"ports" yaml:"ports"`
	// PortPreset selects an embedded list. Recognised values:
	//   "top100"   - nmap top-100 by frequency (default)
	//   "top1000"  - nmap top-1000 by frequency
	//   "all"      - every TCP port 1..65535 (slow!)
	//   ""         - empty == top100
	PortPreset string `json:"port_preset" yaml:"port_preset"`
	// PortRange is a textual port spec like "80,443,8000-8100,9200".
	// When non-empty it overrides PortPreset.
	PortRange string `json:"port_range" yaml:"port_range"`
	// Concurrency caps the total number of in-flight TCP connect attempts
	// across all targets. Defaults to 500.
	Concurrency int `json:"concurrency" yaml:"concurrency"`
	// PerHostConcurrency caps simultaneous connections to a single target.
	// Critical for avoiding RST cascades from SYN-flood mitigations.
	// Defaults to 20.
	PerHostConcurrency int `json:"per_host_concurrency" yaml:"per_host_concurrency"`
	// Timeout is the first-attempt connection timeout. Defaults to 1s.
	Timeout time.Duration `json:"timeout" yaml:"timeout"`
	// RetryTimeout is the timeout used for retry attempts. Defaults to 3s.
	RetryTimeout time.Duration `json:"retry_timeout" yaml:"retry_timeout"`
	// RetryPerPort is the number of retries on transient errors (timeout,
	// reset, refused-with-icmp). Defaults to 2.
	RetryPerPort int `json:"retry_per_port" yaml:"retry_per_port"`
	// GrabBanner enables banner grabbing on open ports. Defaults to true.
	GrabBanner bool `json:"grab_banner" yaml:"grab_banner"`
	// BannerTimeout caps how long we wait for unsolicited banner bytes.
	// Defaults to 1500ms.
	BannerTimeout time.Duration `json:"banner_timeout" yaml:"banner_timeout"`
	// BannerMaxBytes caps the banner read length. Defaults to 256.
	BannerMaxBytes int `json:"banner_max_bytes" yaml:"banner_max_bytes"`
	// SkipResolve disables DNS resolution; useful when caller already
	// resolved targets to IP literals. Defaults to false.
	SkipResolve bool `json:"skip_resolve" yaml:"skip_resolve"`
}

// Normalize fills in defaults for unset fields.
func (c *Config) Normalize() {
	if c.Concurrency <= 0 {
		c.Concurrency = 500
	}
	if c.PerHostConcurrency <= 0 {
		c.PerHostConcurrency = 20
	}
	if c.Timeout <= 0 {
		c.Timeout = 1 * time.Second
	}
	if c.RetryTimeout <= 0 {
		c.RetryTimeout = 3 * time.Second
	}
	if c.RetryPerPort < 0 {
		c.RetryPerPort = 0
	}
	if c.BannerTimeout <= 0 {
		c.BannerTimeout = 1500 * time.Millisecond
	}
	if c.BannerMaxBytes <= 0 {
		c.BannerMaxBytes = 256
	}
	if c.PortPreset == "" && len(c.Ports) == 0 && c.PortRange == "" {
		c.PortPreset = "top100"
	}
}

// Result describes a single open port discovery.
type Result struct {
	// Target is the original input string the user supplied (host or IP).
	Target string `json:"target"`
	// IP is the resolved IPv4/IPv6 address actually probed.
	IP string `json:"ip"`
	// Port is the open TCP port.
	Port int `json:"port"`
	// Service is the well-known service name guessed from the port number
	// (e.g. "http", "ssh"). Empty when the port is not in the IANA table.
	Service string `json:"service,omitempty"`
	// Banner is the first up to BannerMaxBytes received after connect, with
	// non-printable bytes replaced. Empty when GrabBanner is false or the
	// service stayed silent.
	Banner string `json:"banner,omitempty"`
	// LatencyMS records connect latency in milliseconds.
	LatencyMS int64 `json:"latency_ms"`
	// Attempts is how many TCP connect attempts were needed before success.
	Attempts int `json:"attempts"`
}

// ToAsset converts the open-port result to a *models.Asset for session storage.
func (r *Result) ToAsset() *models.Asset {
	a := models.NewAsset()
	a.IP = r.IP
	a.Domain = r.Target
	a.Host = r.Target
	a.Source = "portscan"
	a.UpdateTime = time.Now().UTC().Format(time.RFC3339)
	raw := map[string]string{
		"port": itoa(r.Port),
	}
	if r.Service != "" {
		raw["service"] = r.Service
	}
	if r.Banner != "" {
		raw["banner"] = r.Banner
	}
	if r.LatencyMS > 0 {
		raw["latency_ms"] = itoa(int(r.LatencyMS))
	}
	a.Raw = raw
	return a
}

// itoa is strconv.Itoa without the import dependency from this small file.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
