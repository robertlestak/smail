package cli

import (
	"encoding/base64"
	"errors"
	"flag"
	"io/ioutil"
	"os"

	"github.com/robertlestak/smail/internal/imap"
	"github.com/robertlestak/smail/internal/smtp"
	log "github.com/sirupsen/logrus"
)

func cmdProxy() error {
	l := log.WithFields(log.Fields{
		"cmd": "proxy",
	})
	l.Debug("starting proxy")
	proxyCmd := flag.NewFlagSet("proxy", flag.ExitOnError)
	addr := proxyCmd.String("addr", "", "smail addr to proxy")
	privateKeyPath := proxyCmd.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := proxyCmd.String("privkey-base64", "", "base64 encoded private key")
	smtpPort := proxyCmd.String("smtp-port", "2525", "port to listen on for SMTP")
	smtpDomain := proxyCmd.String("smtp-domain", "", "domain to listen on for SMTP")
	smtpTlsCaPath := proxyCmd.String("smtp-tls-ca", "", "path to TLS CA for SMTP")
	smtpTlsCrtPath := proxyCmd.String("smtp-tls-crt", "", "path to TLS certificate for SMTP")
	smtpTlsKeyPath := proxyCmd.String("smtp-tls-key", "", "path to TLS key for SMTP")
	smtpAllowInsecureAuth := proxyCmd.Bool("smtp-allow-insecure-auth", false, "allow insecure authentication for SMTP")
	imapPort := proxyCmd.String("imap-port", "1143", "port to listen on for IMAP")
	imapDomain := proxyCmd.String("imap-domain", "", "domain to listen on for IMAP")
	imapTlsCaPath := proxyCmd.String("imap-tls-ca", "", "path to TLS CA for IMAP")
	imapTlsCrtPath := proxyCmd.String("imap-tls-crt", "", "path to TLS certificate for IMAP")
	imapTlsKeyPath := proxyCmd.String("imap-tls-key", "", "path to TLS key for IMAP")
	imapAllowInsecureAuth := proxyCmd.Bool("imap-allow-insecure-auth", false, "allow insecure authentication for IMAP")
	imapUser := proxyCmd.String("imap-user", "", "username for IMAP")
	imapPass := proxyCmd.String("imap-pass", "", "password for IMAP")
	serverProto := proxyCmd.String("server-proto", "https", "protocol to use for server")
	serverAddr := proxyCmd.String("server-addr", "", "address of the server")
	proxyCmd.Parse(os.Args[2:])
	var privKeyBytes []byte
	if *privateKeyPath != "" {
		// read privkey from file
		fd, err := ioutil.ReadFile(*privateKeyPath)
		if err != nil {
			return err
		}
		privKeyBytes = fd
	}
	if *privateKeyBase64 != "" {
		// decode base64 privkey
		bd, err := base64.StdEncoding.DecodeString(*privateKeyBase64)
		if err != nil {
			return err
		}
		privKeyBytes = bd
	}
	if len(privKeyBytes) == 0 {
		return errors.New("privkey is required")
	}
	imap.UpstreamServerProto = *serverProto
	imap.UpstreamServerAddr = *serverAddr
	go func() {
		if err := smtp.Start(
			*smtpDomain,
			*smtpPort,
			*smtpTlsCaPath,
			*smtpTlsCrtPath,
			*smtpTlsKeyPath,
			*smtpAllowInsecureAuth,
		); err != nil {
			l.WithError(err).Fatal("smtp server failed")
		}
	}()
	go func() {
		if err := imap.Start(
			*imapDomain,
			*imapPort,
			*imapTlsCaPath,
			*imapTlsCrtPath,
			*imapTlsKeyPath,
			*imapAllowInsecureAuth,
			privKeyBytes,
			*addr,
			*imapUser,
			*imapPass,
		); err != nil {
			l.WithError(err).Fatal("imap server failed")
		}
	}()
	select {}
}
