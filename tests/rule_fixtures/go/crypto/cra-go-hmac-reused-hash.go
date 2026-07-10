package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Branch 1: pre-created hash assigned to variable, closure returns it, passed to hmac.New via named var
func badHmacReusedViaNamedFunc(key []byte) []byte {
	// ruleid: cra-go-hmac-reused-hash
	h := sha256.New()
	fn := func() hash.Hash { return h }
	mac := hmac.New(fn, key)
	mac.Write([]byte("msg"))
	return mac.Sum(nil)
}

// Branch 2: inline closure returning pre-created hash
func badHmacReusedInlineClosure(key []byte) []byte {
	// ruleid: cra-go-hmac-reused-hash
	h := sha256.New()
	mac := hmac.New(func() hash.Hash { return h }, key)
	mac.Write([]byte("msg"))
	return mac.Sum(nil)
}

// Branch 3: inline closure returning a typed hash.Hash variable
func badHmacReusedTypedVar(key []byte, h hash.Hash) []byte {
	// ruleid: cra-go-hmac-reused-hash
	mac := hmac.New(func() hash.Hash { return (h) }, key)
	mac.Write([]byte("msg"))
	return mac.Sum(nil)
}

// Safe: pass constructor directly -- a new hash is created on each call
func okHmacFreshConstructor(key []byte) []byte {
	// ok: cra-go-hmac-reused-hash
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("msg"))
	return mac.Sum(nil)
}
