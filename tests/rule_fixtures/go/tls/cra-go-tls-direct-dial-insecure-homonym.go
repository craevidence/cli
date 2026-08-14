package tlsdirect

import (
	securetls "crypto/tls"
	tls "fixturesemantics/applicationtls"
)

func okApplicationDial(address string) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
}

var _ = securetls.VersionTLS13
