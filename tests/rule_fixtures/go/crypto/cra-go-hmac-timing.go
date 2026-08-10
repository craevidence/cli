package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
)

// Branch 1: H used as first arg to bytes.Equal
func badTimingHFirst(key, msg, received []byte) bool {
	// ruleid: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)
	return bytes.Equal(h, received)
}

// Branch 2: H used as second arg to bytes.Equal
func badTimingHSecond(key, msg, received []byte) bool {
	// ruleid: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)
	return bytes.Equal(received, h)
}

// Branch 3: Sum() called inline as first arg to bytes.Equal
func badTimingInlineFirst(key, msg, received []byte) bool {
	// ruleid: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return bytes.Equal(mac.Sum(nil), received)
}

// Branch 4: Sum() called inline as second arg to bytes.Equal
func badTimingInlineSecond(key, msg, received []byte) bool {
	// ruleid: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return bytes.Equal(received, mac.Sum(nil))
}

// Safe: hmac.Equal on an inline Sum() is constant-time
func okTimingInlineHmacEqual(key, msg, received []byte) bool {
	// ok: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hmac.Equal(mac.Sum(nil), received)
}

// Safe: bytes.Equal on a plain digest is not a MAC comparison
func okTimingDigestCompare(data, expected []byte) bool {
	// ok: cra-go-hmac-timing
	h := sha256.New()
	h.Write(data)
	return bytes.Equal(h.Sum(nil), expected)
}

// Safe: use hmac.Equal for constant-time comparison
func okTimingHmacEqual(key, msg, received []byte) bool {
	// ok: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)
	return hmac.Equal(h, received)
}
