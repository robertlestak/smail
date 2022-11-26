package cli

import (
	"errors"
	"flag"
	"os"

	"github.com/robertlestak/smail/internal/server"
	log "github.com/sirupsen/logrus"
)

func cmdServer() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdServer",
	})
	l.Debug("starting")
	serverCmd := flag.NewFlagSet("server", flag.ExitOnError)
	port := serverCmd.String("port", "8080", "port to listen on")
	tlsCrtPath := serverCmd.String("tls-crt", "", "path to TLS certificate")
	tlsKeyPath := serverCmd.String("tls-key", "", "path to TLS key")
	serverCmd.Parse(os.Args[2:])
	return server.Start(*port, *tlsCrtPath, *tlsKeyPath)
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
	default:
		return errors.New("invalid argument")
	}
}
