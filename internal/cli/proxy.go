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
	enableSmtpPlain := proxyCmd.Bool("smtp-plain", false, "enable plain text SMTP server")
	enableSmtpTls := proxyCmd.Bool("smtp-tls", false, "enable TLS SMTP server")
	smtpPort := proxyCmd.String("smtp-port", "2525", "port to listen on for SMTP")
	smtpDomain := proxyCmd.String("smtp-domain", "", "domain to listen on for SMTP")
	smtpTLSPort := proxyCmd.String("smtp-tls-port", "587", "port to listen on for TLS SMTP")
	smtpAllowAnonymous := proxyCmd.Bool("smtp-allow-anonymous", false, "allow anonymous SMTP connections")
	smtpAuthUsername := proxyCmd.String("smtp-user", "", "username for SMTP authentication")
	smtpAuthPassword := proxyCmd.String("smtp-pass", "", "password for SMTP authentication")
	smtpTlsCaPath := proxyCmd.String("smtp-tls-ca", "", "path to TLS CA for SMTP")
	smtpTlsCrtPath := proxyCmd.String("smtp-tls-crt", "", "path to TLS certificate for SMTP")
	smtpTlsKeyPath := proxyCmd.String("smtp-tls-key", "", "path to TLS key for SMTP")
	smtpAllowInsecureAuth := proxyCmd.Bool("smtp-allow-insecure-auth", false, "allow insecure authentication for SMTP")
	enableImapPlain := proxyCmd.Bool("imap-plain", false, "enable plain text IMAP server")
	enableImapTls := proxyCmd.Bool("imap-tls", false, "enable TLS IMAP server")
	imapPort := proxyCmd.String("imap-port", "1143", "port to listen on for IMAP")
	imapTlsPort := proxyCmd.String("imap-tls-port", "993", "port to listen on for TLS IMAP")
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
	if *enableSmtpTls {
		go func() {
			if err := smtp.Start(
				*smtpDomain,
				*smtpTLSPort,
				*smtpTlsCaPath,
				*smtpTlsCrtPath,
				*smtpTlsKeyPath,
				*smtpAllowInsecureAuth,
				*smtpAllowAnonymous,
				*smtpAuthUsername,
				*smtpAuthPassword,
			); err != nil {
				l.WithError(err).Fatal("smtp server failed")
			}
		}()
	}
	if *enableSmtpPlain {
		go func() {
			if err := smtp.Start(
				*smtpDomain,
				*smtpPort,
				*smtpTlsCaPath,
				*smtpTlsCrtPath,
				*smtpTlsKeyPath,
				*smtpAllowInsecureAuth,
				*smtpAllowAnonymous,
				*smtpAuthUsername,
				*smtpAuthPassword,
			); err != nil {
				l.WithError(err).Fatal("smtp server failed")
			}
		}()
	}
	if *enableImapTls {
		go func() {
			if err := imap.Start(
				*imapDomain,
				*imapTlsPort,
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
	}
	if *enableImapPlain {
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
	}
	select {}
}
