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

// Safe: use hmac.Equal for constant-time comparison
func okTimingHmacEqual(key, msg, received []byte) bool {
	// ok: cra-go-hmac-timing
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	h := mac.Sum(nil)
	return hmac.Equal(h, received)
}
