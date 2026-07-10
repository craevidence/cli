package crypto

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
)

// Branch 1: md5.New()
func badMD5New(data []byte) []byte {
	// ruleid: cra-go-weak-hash
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// Branch 2: md5.Sum()
func badMD5Sum(data []byte) [16]byte {
	// ruleid: cra-go-weak-hash
	return md5.Sum(data)
}

// Branch 3: sha1.New()
func badSHA1New(data []byte) []byte {
	// ruleid: cra-go-weak-hash
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// Branch 4: sha1.Sum()
func badSHA1Sum(data []byte) [20]byte {
	// ruleid: cra-go-weak-hash
	return sha1.Sum(data)
}

// Safe: SHA-256 is not weak
func okSHA256(data []byte) [32]byte {
	// ok: cra-go-weak-hash
	return sha256.Sum256(data)
}
