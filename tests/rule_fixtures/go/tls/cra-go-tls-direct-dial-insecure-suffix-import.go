package tlsdirect

import tls "fixturesemantics/crypto/tls"

func okSuffixImportDial(address string) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
}
