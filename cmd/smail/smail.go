package main

import (
	"os"

	"github.com/robertlestak/smail/internal/cli"
	log "github.com/sirupsen/logrus"
)

func init() {
	ll, err := log.ParseLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		ll = log.InfoLevel
	}
	log.SetLevel(ll)
}

func main() {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "main",
	})
	l.Debug("starting")
	if err := cli.Start(); err != nil {
		l.WithError(err).Fatal("cli failed")
	}
}
