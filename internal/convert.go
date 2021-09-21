package internal

import (
	"golang.org/x/crypto/ssh"
)

func ConvertKey(Key interface{}, password string) (interface{}, error) {
	keystring, ok := Key.(string)

	if !ok {
		return Key, nil
	}

	if password != "" {
		return ssh.ParseRawPrivateKeyWithPassphrase([]byte(keystring), []byte(password))
	} else {
		return ssh.ParseRawPrivateKey([]byte(keystring))
	}
}
