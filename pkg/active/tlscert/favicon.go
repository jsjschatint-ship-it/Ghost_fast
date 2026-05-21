package tlscert

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"
)

// fetchFavicon downloads the favicon at `target` and returns its mmh3 hash
// in the same form Shodan/FOFA use: `mmh3.hash(base64.encodebytes(body))`,
// where `encodebytes` is Python's MIME-style 76-char wrapped base64 plus
// trailing newline.
func fetchFavicon(ctx context.Context, client *http.Client, target, ua string) *FaviconHash {
	t0 := time.Now()
	out := &FaviconHash{URL: target}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		out.Err = err.Error()
		out.DurationMS = time.Since(t0).Milliseconds()
		return out
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "image/x-icon,image/*,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		out.Err = err.Error()
		out.DurationMS = time.Since(t0).Milliseconds()
		return out
	}
	defer resp.Body.Close()
	out.HTTPStatus = resp.StatusCode

	const maxBody = 4 * 1024 * 1024 // 4 MB favicon cap
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		out.Err = "read: " + err.Error()
		out.DurationMS = time.Since(t0).Milliseconds()
		return out
	}
	out.BodyLen = len(body)
	if len(body) == 0 {
		out.Err = "empty body"
		out.DurationMS = time.Since(t0).Milliseconds()
		return out
	}
	sum := md5.Sum(body)
	out.MD5 = hex.EncodeToString(sum[:])
	out.MMH3 = MMH3HashShodanCompat(body)
	out.DurationMS = time.Since(t0).Milliseconds()
	return out
}

// MMH3HashShodanCompat encodes input as Python's base64.encodebytes (76-char
// wrapped + trailing newline) then runs MMH3-32 with seed 0 and returns the
// signed int32 result that Shodan / FOFA use for `http.favicon.hash:`.
//
// Exported so callers and tests can reuse it.
func MMH3HashShodanCompat(input []byte) int32 {
	return int32(murmur3_32(pyBase64Encode(input), 0)) //nolint:gosec
}

// pyBase64Encode replicates Python `base64.encodebytes(data)`: standard
// base64 alphabet, MIME chunk size of 76 with `\n` line terminator, plus a
// trailing `\n` after the last chunk.
func pyBase64Encode(input []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(input)
	var b strings.Builder
	b.Grow(len(enc) + len(enc)/76 + 2)
	for i := 0; i < len(enc); i += 76 {
		end := i + 76
		if end > len(enc) {
			end = len(enc)
		}
		b.WriteString(enc[i:end])
		b.WriteByte('\n')
	}
	return []byte(b.String())
}

// murmur3_32 is a pure-Go implementation of MurmurHash3 x86_32 with the
// supplied seed. Sufficient for favicon hashing (input ~few KB). Implemented
// inline to avoid pulling another dependency.
//
// Reference: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
func murmur3_32(data []byte, seed uint32) uint32 {
	const (
		c1 uint32 = 0xcc9e2d51
		c2 uint32 = 0x1b873593
	)
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		off := i * 4
		k1 := uint32(data[off]) |
			uint32(data[off+1])<<8 |
			uint32(data[off+2])<<16 |
			uint32(data[off+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> (32 - 15))
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> (32 - 13))
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> (32 - 15))
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// faviconClient builds an HTTP client tuned for favicon fetches: TLS-skip,
// short timeout, follow redirects (some sites 302 to /static/favicon.ico).
func faviconClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			ResponseHeaderTimeout: timeout,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}
