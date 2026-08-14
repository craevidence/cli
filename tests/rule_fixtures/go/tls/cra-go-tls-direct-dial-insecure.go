package tlsdirect

import (
	"crypto/tls"
	"crypto/x509"
	"net"
)

func badDirectDial(address string) (*tls.Conn, error) {
	// ruleid: cra-go-tls-direct-dial-insecure
	return tls.Dial("tcp", address, &tls.Config{InsecureSkipVerify: true})
}

func badDirectDialWithDialer(dialer *net.Dialer, address string) (*tls.Conn, error) {
	// ruleid: cra-go-tls-direct-dial-insecure
	return tls.DialWithDialer(
		dialer,
		"tcp",
		address,
		&tls.Config{InsecureSkipVerify: true},
	)
}

func okVerifiedByDefault(address string) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.Dial("tcp", address, &tls.Config{MinVersion: tls.VersionTLS13})
}

func okExplicitVerification(address string, roots *x509.CertPool) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			intermediates := x509.NewCertPool()
			for _, certificate := range state.PeerCertificates[1:] {
				intermediates.AddCert(certificate)
			}
			_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
				DNSName:       address,
				Roots:         roots,
				Intermediates: intermediates,
			})
			return err
		},
	})
}

func okDirectPeerVerification(address string, roots *x509.CertPool) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.Dial("tcp", address, &tls.Config{
		VerifyPeerCertificate: completePeerVerifier(address, roots),
		InsecureSkipVerify:    true,
	})
}

func okDialerConnectionVerification(
	dialer *net.Dialer,
	address string,
	roots *x509.CertPool,
) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		VerifyConnection:   completeConnectionVerifier(address, roots),
		InsecureSkipVerify: true,
	})
}

func okDialerPeerVerification(
	dialer *net.Dialer,
	address string,
	roots *x509.CertPool,
) (*tls.Conn, error) {
	// ok: cra-go-tls-direct-dial-insecure
	return tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: completePeerVerifier(address, roots),
	})
}

func completeConnectionVerifier(
	address string,
	roots *x509.CertPool,
) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		intermediates := x509.NewCertPool()
		for _, certificate := range state.PeerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       address,
			Roots:         roots,
			Intermediates: intermediates,
		})
		return err
	}
}

func completePeerVerifier(
	address string,
	roots *x509.CertPool,
) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		certificates := make([]*x509.Certificate, 0, len(rawCerts))
		for _, rawCertificate := range rawCerts {
			certificate, err := x509.ParseCertificate(rawCertificate)
			if err != nil {
				return err
			}
			certificates = append(certificates, certificate)
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range certificates[1:] {
			intermediates.AddCert(certificate)
		}
		_, err := certificates[0].Verify(x509.VerifyOptions{
			DNSName:       address,
			Roots:         roots,
			Intermediates: intermediates,
		})
		return err
	}
}
