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

// Bad: InsecureSkipVerify assigned to the field after construction
func badInsecureSkipVerifyFieldAssignment() *tls.Config {
	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	// ruleid: cra-go-tls-insecure
	conf.InsecureSkipVerify = true
	return conf
}

// Bad: field assignment on a value rather than a pointer
func badInsecureSkipVerifyValueAssignment() tls.Config {
	var conf tls.Config
	// ruleid: cra-go-tls-insecure
	conf.InsecureSkipVerify = true
	return conf
}

// Safe: the field is assigned false
func okInsecureSkipVerifyFieldAssignedFalse() *tls.Config {
	conf := &tls.Config{MinVersion: tls.VersionTLS13}
	// ok: cra-go-tls-insecure
	conf.InsecureSkipVerify = false
	return conf
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

// Safe: the field is assigned from a variable, not the literal true
func okInsecureSkipVerifyFromVariable(skip bool) *tls.Config {
	conf := &tls.Config{MinVersion: tls.VersionTLS13}
	// ok: cra-go-tls-insecure
	conf.InsecureSkipVerify = skip
	return conf
}

// An unrelated type that declares a field with the same name
type clientOptions struct {
	InsecureSkipVerify bool
}

// Safe: the receiver is not a tls.Config
func okUnrelatedStructValue() clientOptions {
	var opts clientOptions
	// ok: cra-go-tls-insecure
	opts.InsecureSkipVerify = true
	return opts
}

// Safe: the receiver is a pointer to the unrelated type
func okUnrelatedStructPointer() *clientOptions {
	opts := &clientOptions{}
	// ok: cra-go-tls-insecure
	opts.InsecureSkipVerify = true
	return opts
}

// A minimal error value so the verification callback below can reject without
// pulling another import into this fixture.
type peerCertificateMissing struct{}

func (peerCertificateMissing) Error() string { return "no peer certificate" }

// Safe: the standard check is turned off but the configuration installs its own
// certificate check in the same literal.
func okInsecureSkipVerifyWithConnectionVerification() *tls.Config {
	// ok: cra-go-tls-insecure
	return &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return peerCertificateMissing{}
			}
			return nil
		},
	}
}

// Safe: the same, with the peer check taken from a pinned configuration and
// installed on the value afterwards.
func okInsecureSkipVerifyThenPeerVerification(pinned *tls.Config) *tls.Config {
	conf := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}
	// ok: cra-go-tls-insecure
	conf.VerifyPeerCertificate = pinned.VerifyPeerCertificate
	return conf
}

// Safe: the field assignment form followed by a connection check.
func okInsecureSkipVerifyThenConnectionCheck(conf *tls.Config) {
	// ok: cra-go-tls-insecure
	conf.InsecureSkipVerify = true
	conf.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return peerCertificateMissing{}
		}
		return nil
	}
}
