package internal

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"sync"
)

type privKey struct {
	signer   ssh.Signer
	comment  string
	priority int
}

type CustomAgent struct {
	mu       sync.Mutex
	keys     []privKey
	loaded   bool
	loadKeys loadKeysFunction
}

type loadKeysFunction = func() error

func NewAgent(load loadKeysFunction) *CustomAgent {
	return &CustomAgent{
		loadKeys: load,
	}
}

func (k *CustomAgent) checkLoaded() {
	if !k.loaded {
		err := k.loadKeys()
		if err != nil {
			return
		}
		k.loaded = true
	}
}

func (k *CustomAgent) List() ([]*agent.Key, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.checkLoaded()

	var ids []*agent.Key
	for _, k := range k.keys {
		pub := k.signer.PublicKey()
		ids = append(ids, &agent.Key{
			Format:  pub.Type(),
			Blob:    pub.Marshal(),
			Comment: k.comment})
	}
	return ids, nil
}

func (k *CustomAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return k.SignWithFlags(key, data, 0)
}

func (k *CustomAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	wanted := key.Marshal()
	for _, k := range k.keys {
		if bytes.Equal(k.signer.PublicKey().Marshal(), wanted) {
			if flags == 0 {
				return k.signer.Sign(rand.Reader, data)
			} else {
				if algorithmSigner, ok := k.signer.(ssh.AlgorithmSigner); !ok {
					return nil, fmt.Errorf("agent: signature does not support non-default signature algorithm: %T", k.signer)
				} else {
					var algorithm string
					switch flags {
					case agent.SignatureFlagRsaSha256:
						algorithm = ssh.SigAlgoRSASHA2256
					case agent.SignatureFlagRsaSha512:
						algorithm = ssh.SigAlgoRSASHA2512
					default:
						return nil, fmt.Errorf("agent: unsupported signature flags: %d", flags)
					}
					return algorithmSigner.SignWithAlgorithm(rand.Reader, data, algorithm)
				}
			}
		}
	}
	return nil, errors.New("not found")
}

func (k *CustomAgent) Signers() ([]ssh.Signer, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.checkLoaded()
	s := make([]ssh.Signer, 0, len(k.keys))
	for _, k := range k.keys {
		s = append(s, k.signer)
	}
	return s, nil
}

func (k *CustomAgent) AddInternal(key interface{}, comment string, priority int, password string) error {
	key, err := ConvertKey(key, password)
	if err != nil {
		return err
	}

	signer, err := ssh.NewSignerFromKey(key)

	if err != nil {
		return err
	}

	p := privKey{
		signer:   signer,
		comment:  comment,
		priority: priority,
	}

	var insert = len(k.keys)
	for i := range k.keys {
		if priority > k.keys[i].priority {
			insert = i
			break
		}
	}

	if insert < len(k.keys) {
		k.keys = append(k.keys[:insert+1], k.keys[insert:]...)
		k.keys[insert] = p
	} else {
		k.keys = append(k.keys, p)
	}

	return nil
}

func (k *CustomAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}

func (k *CustomAgent) Add(key agent.AddedKey) error {
	return errors.New("adding not supported")
}

func (k *CustomAgent) Remove(key ssh.PublicKey) error {
	return errors.New("removing not supported")
}

func (k *CustomAgent) RemoveAll() error {
	return errors.New("removing not supported")
}

func (k *CustomAgent) Lock(passphrase []byte) error {
	return errors.New("locking not supported")
}

func (k *CustomAgent) Unlock(passphrase []byte) error {
	return errors.New("locking not supported")
}
