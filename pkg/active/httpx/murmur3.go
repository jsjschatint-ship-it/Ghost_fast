package httpx

import (
	"encoding/base64"
	"strconv"
)

// Mmh3FaviconHash returns the "favicon hash" used by FOFA / Shodan: a 32-bit
// signed integer produced by hashing the base64-encoded favicon bytes
// (with a trailing newline, as Python's base64.encodebytes adds).
//
// The hash function is MurmurHash3_x86_32 with seed 0.
func Mmh3FaviconHash(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	encoded := base64Encode(data)
	h := murmur3X8632(encoded, 0)
	return strconv.FormatInt(int64(int32(h)), 10)
}

// base64Encode emulates Python's base64.encodebytes: standard-encode the input,
// then break into 76-char lines with '\n' separators, and append a trailing '\n'.
func base64Encode(data []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(data)
	const lineLen = 76
	out := make([]byte, 0, len(enc)+len(enc)/lineLen+1)
	for i := 0; i < len(enc); i += lineLen {
		j := i + lineLen
		if j > len(enc) {
			j = len(enc)
		}
		out = append(out, enc[i:j]...)
		out = append(out, '\n')
	}
	return out
}

// murmur3X8632 implements MurmurHash3 x86_32 (single-shot).
//
// Reference: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
func murmur3X8632(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h1 := seed
	n := len(data)
	nblocks := n / 4
	for i := 0; i < nblocks; i++ {
		k1 := uint32(data[i*4]) | uint32(data[i*4+1])<<8 | uint32(data[i*4+2])<<16 | uint32(data[i*4+3])<<24
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	var k1 uint32
	switch n & 3 {
	case 3:
		k1 ^= uint32(data[nblocks*4+2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(data[nblocks*4+1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(data[nblocks*4])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(n)
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}
