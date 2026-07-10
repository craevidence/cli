package tls

import (
	"crypto/tls"
	"net/http"
)

// Bad: InsecureSkipVerify set to true
func badInsecureSkipVerify() *http.Client {
	tr := &http.Transport{
		// ruleid: cra-go-tls-insecure
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	return &http.Client{Transport: tr}
}

// Bad: InsecureSkipVerify true with other fields present
func badInsecureSkipVerifyWithFields() *tls.Config {
	// ruleid: cra-go-tls-insecure
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
}

// Safe: InsecureSkipVerify not set (defaults to false)
func okDefaultTLSConfig() *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	// ok: cra-go-tls-insecure
	return &http.Client{Transport: tr}
}

// Safe: InsecureSkipVerify explicitly false
func okInsecureSkipVerifyFalse() *tls.Config {
	// ok: cra-go-tls-insecure
	return &tls.Config{InsecureSkipVerify: false}
}
