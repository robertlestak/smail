package imap

import (
	"errors"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	log "github.com/sirupsen/logrus"
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
	l := log.WithFields(log.Fields{
		"app": "imap",
		"fn":  "Login",
	})
	l.Debug("Login attempt")
	user, ok := be.Users[username]
	if ok && user.password == password {
		l.Debug("Login successful")
		return user, nil
	}
	l.Debug("Login failed")
	return nil, errors.New("bad username or password")
}

func NewBackend(privKeyBytes []byte, addr, username, password string) *Backend {
	l := log.WithFields(log.Fields{
		"app": "imap",
		"fn":  "NewBackend",
	})
	l.Debug("Creating new backend")
	user := &User{username: username, password: password, Address: addr}
	user.mailboxes = map[string]*Mailbox{
		"INBOX": {
			name: "INBOX",
			user: user,
		},
	}
	PrivateKeyBytes = privKeyBytes
	l.Debug("New backend created")
	return &Backend{
		Users: map[string]*User{user.username: user},
	}
}
