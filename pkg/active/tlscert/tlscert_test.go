package tlscert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
)

// TestMurmur3KnownVectors locks in MurmurHash3 x86_32 against well-known
// reference vectors (matches Python `mmh3.hash(s, 0)` interpreted as signed
// int32 — the same form Shodan/FOFA use for `http.favicon.hash:`).
//
// Vectors verified against the Python `mmh3` package:
//
//	mmh3.hash(b"")    →  0
//	mmh3.hash(b"foo") → -156908512
//	mmh3.hash(b"hello") → 613153351
func TestMurmur3KnownVectors(t *testing.T) {
	cases := []struct {
		in   string
		want int32
	}{
		{"", 0},
		{"foo", -156908512},
		{"hello", 613153351},
	}
	for _, c := range cases {
		got := int32(murmur3_32([]byte(c.in), 0)) //nolint:gosec
		if got != c.want {
			t.Errorf("murmur3_32(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// TestMMH3FaviconWireFormat: hashing the same input twice must yield the same
// value, and the value must change if the input changes by one byte. This
// guarantees deterministic + content-sensitive output without locking to a
// specific reference value (Shodan-compatibility is checked structurally
// via TestMurmur3KnownVectors + TestPyBase64EncodeMatchesPython).
func TestMMH3FaviconWireFormat(t *testing.T) {
	a := MMH3HashShodanCompat([]byte("hello"))
	b := MMH3HashShodanCompat([]byte("hello"))
	if a != b {
		t.Fatalf("non-deterministic: %d vs %d", a, b)
	}
	c := MMH3HashShodanCompat([]byte("hellp"))
	if a == c {
		t.Errorf("collision between 'hello' and 'hellp'")
	}
}

// TestPyBase64EncodeMatchesPython locks in MIME-style 76-wrap + trailing newline.
func TestPyBase64EncodeMatchesPython(t *testing.T) {
	in := strings.Repeat("a", 60) // 60 bytes → 80 b64 chars → wraps at 76
	got := string(pyBase64Encode([]byte(in)))
	// Python `base64.encodebytes` would produce "<76 chars>\n<4 chars>\n".
	if !strings.HasSuffix(got, "\n") {
		t.Fatal("missing trailing newline")
	}
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 2 || len(lines[0]) != 76 {
		t.Fatalf("expected 2 lines (76 + tail), got %v", lines)
	}
}

// TestSplitHostPort covers the URL-stripping edge cases.
func TestSplitHostPort(t *testing.T) {
	cases := map[string][2]string{
		"example.com":            {"example.com", "443"},
		"example.com:8443":       {"example.com", "8443"},
		"https://example.com/":   {"example.com", "443"},
		"https://example.com:9/": {"example.com", "9"},
	}
	for in, want := range cases {
		h, p := splitHostPort(in)
		if h != want[0] || p != want[1] {
			t.Errorf("splitHostPort(%q) = (%q, %q), want %v", in, h, p, want)
		}
	}
}

// TestFaviconFetch spins up an httptest server returning a 16-byte fake
// favicon and verifies fetchFavicon hashes it correctly.
func TestFaviconFetch(t *testing.T) {
	body := []byte("\x00\x00\x01\x00\x01\x00\x10\x10\x00\x00\x00\x00\x00\x00")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	client := faviconClient(5 * time.Second)
	got := fetchFavicon(context.Background(), client, srv.URL+"/favicon.ico", "test-ua")
	if got.Err != "" {
		t.Fatalf("err: %s", got.Err)
	}
	if got.HTTPStatus != 200 {
		t.Errorf("status = %d", got.HTTPStatus)
	}
	if got.BodyLen != len(body) {
		t.Errorf("body_len = %d", got.BodyLen)
	}
	if got.MMH3 == 0 {
		t.Error("mmh3 should be non-zero")
	}
	if len(got.MD5) != 32 {
		t.Errorf("md5 should be 32 hex chars, got %q", got.MD5)
	}
	// Cross-check: independent computation must agree.
	if want := MMH3HashShodanCompat(body); got.MMH3 != want {
		t.Errorf("mmh3 mismatch: got %d, want %d", got.MMH3, want)
	}
}

// TestLiveTLSAgainstHTTPTest spins up an httptest TLS server with a self-signed
// cert and verifies fetchCert pulls back the SAN list + fingerprint.
func TestLiveTLSAgainstHTTPTest(t *testing.T) {
	cert := selfSignedCert(t, "tlscert.test", []string{"tlscert.test", "alt.tlscert.test"})
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()

	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	info := fetchCert(context.Background(), host+":"+port, 4*time.Second)
	if info.Err != "" {
		t.Fatalf("err: %s", info.Err)
	}
	if info.SHA256 == "" {
		t.Error("sha256 missing")
	}
	if !info.IsSelfSign {
		t.Errorf("expected self-signed flag for self-signed cert")
	}
	if len(info.SANs) < 2 {
		t.Errorf("expected ≥2 SANs, got %v", info.SANs)
	}
	gotSANs := strings.Join(info.SANs, ",")
	if !strings.Contains(gotSANs, "tlscert.test") {
		t.Errorf("expected tlscert.test in SANs, got %v", info.SANs)
	}
}

// selfSignedCert builds an ephemeral ECDSA cert. Helper for the test above.
func selfSignedCert(t *testing.T, cn string, sans []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		DNSNames:     sans,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("X509KeyPair: %v", err)
	}
	return cert
}

// Smoke check for runner end-to-end (favicon-only stage to keep it offline).
func TestRunFaviconOnly(t *testing.T) {
	body := []byte("ICONICONICONICON")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	res := Run(context.Background(), Config{
		FaviconURLs: []string{srv.URL + "/favicon.ico"},
		DoFavicon:   true,
	})
	if len(res.Favicons) != 1 {
		t.Fatalf("expected 1 favicon, got %d", len(res.Favicons))
	}
	if res.Stats.FaviconsHashed != 1 {
		t.Errorf("stats: %+v", res.Stats)
	}
	// belt-and-braces: ensure no crashing if exec.LookPath gets queried somewhere
	_, _ = exec.LookPath("nonexistent-binary")
}
