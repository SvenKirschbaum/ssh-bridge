package static

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/fallobst22/ssh-bridge/internal"
)

type Supplier struct {
}

func (*Supplier) Init() error {

	return nil
}

func (*Supplier) Keys() ([]internal.PlainKey, error) {
	decode, _ := pem.Decode([]byte("<KEY>"))
	key, _ := x509.ParsePKCS1PrivateKey(decode.Bytes)

	return []internal.PlainKey{
		{
			Key:     key,
			Comment: "Static QuickEScan Key",
		},
	}, nil
}
