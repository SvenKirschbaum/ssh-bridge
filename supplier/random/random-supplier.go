package random

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/fallobst22/ssh-bridge/internal"
)

type Supplier struct {
}

func (*Supplier) Init() error {
	return nil
}

func (*Supplier) Keys() ([]internal.PlainKey, error) {
	generateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return []internal.PlainKey{
		{
			Key:     generateKey,
			Comment: "Random Key",
		},
	}, nil
}
