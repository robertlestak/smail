package cli

import (
	"errors"
	"flag"
	"os"

	"github.com/robertlestak/smail/internal/server"
	"github.com/robertlestak/smail/internal/smtp"
	log "github.com/sirupsen/logrus"
)

func cmdServer() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdServer",
	})
	l.Debug("starting")
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	serverAddr := serverCmd.String("addr", "", "address to listen on")
	port := serverCmd.String("port", "8080", "port to listen on")
	tlsCrtPath := serverCmd.String("tls-crt", "", "path to TLS certificate")
	tlsKeyPath := serverCmd.String("tls-key", "", "path to TLS key")

	enableSmtp := serverCmd.Bool("enable-smtp", false, "enable SMTP server")
	smtpPort := serverCmd.String("smtp-port", "2525", "port to listen on for SMTP")
	smtpDomain := serverCmd.String("smtp-domain", "", "domain to listen on for SMTP")
	smtpTlsCaPath := serverCmd.String("smtp-tls-ca", "", "path to TLS CA for SMTP")
	smtpTlsCrtPath := serverCmd.String("smtp-tls-crt", "", "path to TLS certificate for SMTP")
	smtpTlsKeyPath := serverCmd.String("smtp-tls-key", "", "path to TLS key for SMTP")
	smtpAllowInsecureAuth := serverCmd.Bool("smtp-allow-insecure-auth", false, "allow insecure authentication for SMTP")
	serverCmd.Parse(os.Args[2:])
	go func() {
		if err := server.Start(*serverAddr, *port, *tlsCrtPath, *tlsKeyPath); err != nil {
			l.WithError(err).Fatal("server failed")
		}
	}()
	if *enableSmtp {
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
	}
	select {}
}

func Start() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "Start",
	})
	l.Debug("starting")
	var arg string
	if len(os.Args) > 1 {
		arg = os.Args[1]
	}
	switch arg {
	case "server":
		return cmdServer()
	case "addr":
		return cmdAddr()
	case "msg":
		return cmdMsg()
	case "sig":
		return cmdSig()
	case "proxy":
		return cmdProxy()
	default:
		return errors.New("invalid argument")
	}
}
