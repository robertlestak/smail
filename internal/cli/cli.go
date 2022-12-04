package cli

import (
	"errors"
	"flag"
	"os"

	"github.com/robertlestak/smail/internal/persist"
	"github.com/robertlestak/smail/internal/server"
	"github.com/robertlestak/smail/internal/smtp"
	"github.com/robertlestak/smail/pkg/address"
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
	publicKeyPath := serverCmd.String("public-key", "", "path to public key")
	enableSmtpPlain := serverCmd.Bool("smtp-plain", false, "enable plain text SMTP server")
	enableSmtpTls := serverCmd.Bool("smtp-tls", false, "enable TLS SMTP server")
	smtpPort := serverCmd.String("smtp-port", "2525", "port to listen on for SMTP")
	smtpDomain := serverCmd.String("smtp-domain", "", "domain to listen on for SMTP")
	smtpAllowAnonymous := serverCmd.Bool("smtp-allow-anonymous", false, "allow anonymous SMTP connections")
	smtpAuthUsername := serverCmd.String("smtp-user", "", "username for SMTP authentication")
	smtpAuthPassword := serverCmd.String("smtp-pass", "", "password for SMTP authentication")
	smtpTLSPort := serverCmd.String("smtp-tls-port", "587", "port to listen on for TLS SMTP")
	smtpTlsCaPath := serverCmd.String("smtp-tls-ca", "", "path to TLS CA for SMTP")
	smtpTlsCrtPath := serverCmd.String("smtp-tls-crt", "", "path to TLS certificate for SMTP")
	smtpTlsKeyPath := serverCmd.String("smtp-tls-key", "", "path to TLS key for SMTP")
	smtpAllowInsecureAuth := serverCmd.Bool("smtp-allow-insecure-auth", false, "allow insecure authentication for SMTP")
	persistDriver := serverCmd.String("persist-driver", "fs", "database driver to use")
	persistFSDataDir := serverCmd.String("persist-fs-data-dir", "", "path to data directory for fs driver")
	serverCmd.Parse(os.Args[2:])
	// init persistence
	dn := persist.DriverName(*persistDriver)
	if dn == "" && os.Getenv("PERSIST_DRIVER") != "" {
		dn = persist.DriverName(os.Getenv("PERSIST_DRIVER"))
	}
	d, err := persist.LoadDriver(dn)
	if err != nil {
		return err
	}
	switch dn {
	case persist.DriverFS:
		if *persistFSDataDir == "" && os.Getenv("PERSIST_FS_DATA_DIR") != "" {
			*persistFSDataDir = os.Getenv("PERSIST_FS_DATA_DIR")
		}
		if *persistFSDataDir == "" {
			return errors.New("data directory must be specified for fs driver")
		}
		d.(*persist.FS).DataDir = *persistFSDataDir
	}
	if err := d.Init(); err != nil {
		return err
	}
	// init server
	go func() {
		if err := address.LoadServerPublicKey(*publicKeyPath); err != nil {
			l.WithError(err).Error("failed to load public key")
			os.Exit(1)
		}
		if err := server.Start(*serverAddr, *port, *tlsCrtPath, *tlsKeyPath); err != nil {
			l.WithError(err).Fatal("server failed")
		}
	}()
	// init smtp
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
