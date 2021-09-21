package internal

import "golang.org/x/crypto/ssh/agent"

type PlainKey struct {
	Key      interface{}
	Comment  string
	Priority int
	Password string
}

type Supplier interface {
	Init() error
	Keys() ([]PlainKey, error)
}

type Consumer func(sshAgent agent.Agent)
