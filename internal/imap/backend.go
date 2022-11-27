package imap

import (
	"errors"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
)

var (
	PrivateKeyBytes     []byte
	UpstreamServerProto string
	UpstreamServerAddr  string
)

type Backend struct {
	Users map[string]*User
}

func (be *Backend) Login(_ *imap.ConnInfo, username, password string) (backend.User, error) {
	user, ok := be.Users[username]
	if ok && user.password == password {
		return user, nil
	}

	return nil, errors.New("bad username or password")
}

func NewBackend(privKeyBytes []byte, addr, username, password string) *Backend {
	user := &User{username: username, password: password, Address: addr}
	user.mailboxes = map[string]*Mailbox{
		"INBOX": {
			name: "INBOX",
			user: user,
		},
	}
	PrivateKeyBytes = privKeyBytes
	return &Backend{
		Users: map[string]*User{user.username: user},
	}
}
