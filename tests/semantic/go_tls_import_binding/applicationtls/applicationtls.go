package applicationtls

type Config struct {
	InsecureSkipVerify bool
}

type Conn struct{}

func Dial(_ string, _ string, _ *Config) (*Conn, error) {
	return &Conn{}, nil
}
