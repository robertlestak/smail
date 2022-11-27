package imap

import (
	"github.com/emersion/go-imap/server"
	"github.com/robertlestak/smail/internal/utils"
	log "github.com/sirupsen/logrus"
)

func Start(addr string, port string, tlsCAPath string, tlsCrtPath string, tlsKeyPath string, allowInsecure bool, privKeyBytes []byte, userAddr string, imapUser string, imapPass string) error {
	l := log.WithFields(log.Fields{
		"app": "imap",
		"fn":  "Start",
	})
	l.Debug("starting")
	be := NewBackend(
		privKeyBytes,
		userAddr,
		imapUser,
		imapPass,
	)

	// Create a new server
	s := server.New(be)
	s.Addr = addr + ":" + port
	if tlsCrtPath != "" && tlsKeyPath != "" {
		enableTls := true
		tlsInsecure := false
		t, err := utils.TlsConfig(&enableTls, &tlsInsecure, &tlsCAPath, &tlsCrtPath, &tlsKeyPath)
		if err != nil {
			return err
		}
		s.TLSConfig = t
	}
	l.WithField("addr", s.Addr).Debug("starting server")
	// Since we will use this server for testing only, we can allow plain text
	// authentication over unencrypted connections
	s.AllowInsecureAuth = allowInsecure

	if err := s.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
