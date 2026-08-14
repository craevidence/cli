package tlsdirect

import securetls "crypto/tls"

func badAliasedDirectDial(address string) (*securetls.Conn, error) {
	// ruleid: cra-go-tls-direct-dial-insecure
	return securetls.Dial("tcp", address, &securetls.Config{
		InsecureSkipVerify: true,
	})
}

func okAliasedDirectDial(address string) (*securetls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return securetls.Dial("tcp", address, &securetls.Config{
		MinVersion: securetls.VersionTLS13,
	})
}
