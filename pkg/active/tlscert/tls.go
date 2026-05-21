package tlscert

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"
)

// fetchCert opens a TCP+TLS connection to target and returns the leaf cert
// summarised as CertInfo. target is host[:port]; default port 443.
func fetchCert(ctx context.Context, target string, timeout time.Duration) *CertInfo {
	t0 := time.Now()
	host, port := splitHostPort(target)
	addr := host + ":" + port

	info := &CertInfo{Target: target, Host: host, Port: port}

	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		info.Err = "dial: " + err.Error()
		info.DurationMS = time.Since(t0).Milliseconds()
		return info
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: true, // we WANT to see broken / expired certs
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		info.Err = "handshake: " + err.Error()
		info.DurationMS = time.Since(t0).Milliseconds()
		return info
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	info.NegotiatedV = tlsVersionString(state.Version)

	if len(state.PeerCertificates) == 0 {
		info.Err = "no peer certificates"
		info.DurationMS = time.Since(t0).Milliseconds()
		return info
	}
	leaf := state.PeerCertificates[0]
	info.SubjectCN = leaf.Subject.CommonName
	info.Subject = leaf.Subject.String()
	info.Issuer = leaf.Issuer.String()
	info.NotBefore = leaf.NotBefore
	info.NotAfter = leaf.NotAfter
	info.IsExpired = time.Now().After(leaf.NotAfter)
	if leaf.SerialNumber != nil {
		info.SerialHex = leaf.SerialNumber.Text(16)
	}
	sum := sha256.Sum256(leaf.Raw)
	info.SHA256 = hex.EncodeToString(sum[:])
	// "Self-signed" heuristic: subject == issuer AND only one cert in chain.
	if leaf.Subject.String() == leaf.Issuer.String() && len(state.PeerCertificates) == 1 {
		info.IsSelfSign = true
	}

	// Combine DNS + IP SANs + CN into deduplicated list.
	seen := map[string]struct{}{}
	add := func(s string) {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" {
			return
		}
		if strings.HasPrefix(s, "*.") {
			info.IsWildcard = true
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		info.SANs = append(info.SANs, s)
	}
	for _, n := range leaf.DNSNames {
		add(n)
	}
	for _, ip := range leaf.IPAddresses {
		add(ip.String())
	}
	if leaf.Subject.CommonName != "" {
		add(leaf.Subject.CommonName)
	}
	info.DurationMS = time.Since(t0).Milliseconds()
	return info
}

func splitHostPort(target string) (host, port string) {
	target = strings.TrimSpace(target)
	target = strings.TrimPrefix(target, "https://")
	target = strings.TrimPrefix(target, "http://")
	if i := strings.IndexByte(target, '/'); i >= 0 {
		target = target[:i]
	}
	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, p
	}
	return target, "443"
}

func tlsVersionString(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}
