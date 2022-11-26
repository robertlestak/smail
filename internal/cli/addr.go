package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/robertlestak/smail/internal/encrypt"
	"github.com/robertlestak/smail/pkg/address"
	log "github.com/sirupsen/logrus"
)

func cmdAddrNew() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdAddrNew",
	})
	l.Debug("starting")
	newAddrFlagSet := flag.NewFlagSet("new", flag.ExitOnError)
	name := newAddrFlagSet.String("name", "", "name of the address")
	server := newAddrFlagSet.String("server", "", "server to query")
	serverProto := newAddrFlagSet.String("server-proto", "https", "server protocol")
	domain := newAddrFlagSet.String("domain", "", "domain of the address")
	pubKeyPath := newAddrFlagSet.String("pubkey-path", "", "path to the public key")
	pubKeyBase64 := newAddrFlagSet.String("pubkey-base64", "", "base64 encoded public key")
	privKeyPath := newAddrFlagSet.String("privkey-path", "", "path to the private key")
	privKeyBase64 := newAddrFlagSet.String("privkey-base64", "", "base64 encoded private key")
	output := newAddrFlagSet.String("output", "json", "output format")
	outputPath := newAddrFlagSet.String("output-path", "-", "output path")
	newAddrFlagSet.Parse(os.Args[3:])
	*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	l.WithFields(log.Fields{
		"name":          *name,
		"domain":        *domain,
		"pubkey-path":   *pubKeyPath,
		"pubkey-base64": *pubKeyBase64,
	}).Debug("parsed flags")
	var privKeyBytes []byte
	if *privKeyPath != "" {
		// read privkey from file
		fd, err := ioutil.ReadFile(*privKeyPath)
		if err != nil {
			return err
		}
		privKeyBytes = fd
	} else if *privKeyBase64 != "" {
		// decode base64 privkey
		bd, err := base64.StdEncoding.DecodeString(*privKeyBase64)
		if err != nil {
			return err
		}
		privKeyBytes = bd
	} else {
		return errors.New("privkey is required")
	}
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	var pubKeyBytes []byte
	if *pubKeyPath != "" {
		// read pubkey from file
		fd, err := ioutil.ReadFile(*pubKeyPath)
		if err != nil {
			return err
		}
		pubKeyBytes = fd
	} else if *pubKeyBase64 != "" {
		// decode base64 pubkey
		bd, err := base64.StdEncoding.DecodeString(*pubKeyBase64)
		if err != nil {
			return err
		}
		pubKeyBytes = bd
	} else {
		return errors.New("pubkey is required")
	}
	addr, err := address.CreateAddress(
		*server,
		sig,
		*name,
		*domain,
		pubKeyBytes,
	)
	if err != nil {
		return err
	}
	return outputData(addr, *output, *outputPath)
}

func outputData(data any, format string, location string) error {
	var bd []byte
	var err error
	switch format {
	case "json":
		bd, err = json.Marshal(data)
		if err != nil {
			return err
		}
	case "yaml":
		bd, err = yaml.Marshal(data)
		if err != nil {
			return err
		}
	case "table":
		// TODO
		return errors.New("table output not implemented")
	default:
		return errors.New("invalid output format")
	}
	if location == "-" || location == "" {
		os.Stdout.Write(bd)
	} else {
		if err := ioutil.WriteFile(location, bd, 0644); err != nil {
			return err
		}
	}
	return nil
}

func cmdAddrList() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdAddrList",
	})
	l.Debug("starting")
	listAddrFlagSet := flag.NewFlagSet("list", flag.ExitOnError)
	output := listAddrFlagSet.String("output", "json", "output format")
	outputPath := listAddrFlagSet.String("output-path", "-", "output path")
	server := listAddrFlagSet.String("server", "", "server to query")
	serverProto := listAddrFlagSet.String("server-proto", "https", "server protocol")
	page := listAddrFlagSet.Int("page", 0, "page number")
	pageSize := listAddrFlagSet.Int("page-size", 10, "page size")
	privKeyPath := listAddrFlagSet.String("privkey-path", "", "path to the private key")
	privKeyBase64 := listAddrFlagSet.String("privkey-base64", "", "base64 encoded private key")
	listAddrFlagSet.Parse(os.Args[3:])
	var privKeyBytes []byte
	if *privKeyPath != "" {
		// read privkey from file
		fd, err := ioutil.ReadFile(*privKeyPath)
		if err != nil {
			return err
		}
		privKeyBytes = fd
	} else if *privKeyBase64 != "" {
		// decode base64 privkey
		bd, err := base64.StdEncoding.DecodeString(*privKeyBase64)
		if err != nil {
			return err
		}
		privKeyBytes = bd
	} else {
		return errors.New("privkey is required")
	}
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		return errors.New("server is required")
	}
	*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	addrs, err := address.ListAddresses(*server, sig, *page, *pageSize)
	if err != nil {
		return err
	}
	return outputData(addrs, *output, *outputPath)
}

func cmdAddrDelete() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdAddrDelete",
	})
	l.Debug("starting")
	deleteAddrFlagSet := flag.NewFlagSet("delete", flag.ExitOnError)
	id := deleteAddrFlagSet.String("id", "", "id of the address")
	serverProto := deleteAddrFlagSet.String("server-proto", "https", "server protocol")
	server := deleteAddrFlagSet.String("server", "", "server to query")
	privKeyPath := deleteAddrFlagSet.String("privkey-path", "", "path to the private key")
	privKeyBase64 := deleteAddrFlagSet.String("privkey-base64", "", "base64 encoded private key")
	deleteAddrFlagSet.Parse(os.Args[3:])
	l.WithField("id", *id).Debug("parsed flags")
	if *id == "" {
		return errors.New("id is required")
	}
	var privKeyBytes []byte
	if *privKeyPath != "" {
		// read privkey from file
		fd, err := ioutil.ReadFile(*privKeyPath)
		if err != nil {
			return err
		}
		privKeyBytes = fd
	} else if *privKeyBase64 != "" {
		// decode base64 privkey
		bd, err := base64.StdEncoding.DecodeString(*privKeyBase64)
		if err != nil {
			return err
		}
		privKeyBytes = bd
	} else {
		return errors.New("privkey is required")
	}
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		return errors.New("server is required")
	}
	*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	return address.DeleteAddress(*server, sig, *id)
}

func cmdAddrUpdate() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdAddrUpdate",
	})
	l.Debug("starting")
	updateAddrFlagSet := flag.NewFlagSet("update", flag.ExitOnError)
	id := updateAddrFlagSet.String("id", "", "id of the address")
	server := updateAddrFlagSet.String("server", "", "server to query")
	serverProto := updateAddrFlagSet.String("server-proto", "https", "server protocol")
	pubKeyPath := updateAddrFlagSet.String("pubkey-path", "", "path to the public key")
	pubKeyBase64 := updateAddrFlagSet.String("pubkey-base64", "", "base64 encoded public key")
	privKeyPath := updateAddrFlagSet.String("privkey-path", "", "path to the private key")
	privKeyBase64 := updateAddrFlagSet.String("privkey-base64", "", "base64 encoded private key")
	updateAddrFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"id":            *id,
		"pubkey-path":   *pubKeyPath,
		"pubkey-base64": *pubKeyBase64,
	}).Debug("parsed flags")
	if *id == "" {
		return errors.New("id is required")
	}
	var pubKeyBytes []byte
	if *pubKeyPath != "" {
		// read pubkey from file
		fd, err := ioutil.ReadFile(*pubKeyPath)
		if err != nil {
			return err
		}
		pubKeyBytes = fd
	} else if *pubKeyBase64 != "" {
		// decode base64 pubkey
		bd, err := base64.StdEncoding.DecodeString(*pubKeyBase64)
		if err != nil {
			return err
		}
		pubKeyBytes = bd
	} else {
		return errors.New("pubkey is required")
	}
	l.WithField("id", *id).Debug("parsed flags")
	if *id == "" {
		return errors.New("id is required")
	}
	var privKeyBytes []byte
	if *privKeyPath != "" {
		// read privkey from file
		fd, err := ioutil.ReadFile(*privKeyPath)
		if err != nil {
			return err
		}
		privKeyBytes = fd
	} else if *privKeyBase64 != "" {
		// decode base64 privkey
		bd, err := base64.StdEncoding.DecodeString(*privKeyBase64)
		if err != nil {
			return err
		}
		privKeyBytes = bd
	} else {
		return errors.New("privkey is required")
	}
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		return errors.New("server is required")
	}
	*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	var a address.Address
	a.ID = *id
	a.PubKey = pubKeyBytes
	jd, err := json.Marshal(a)
	if err != nil {
		return err
	}
	req, err := http.NewRequest("PUT", *server+"/address/"+*id+"/pubkey", bytes.NewBuffer(jd))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", sig)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func cmdAddr() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdAddr",
	})
	l.Debug("starting")
	// subcommands
	// addr new
	// addr list
	// addr delete
	// addr update
	var arg string
	if len(os.Args) > 2 {
		arg = os.Args[2]
	}
	switch arg {
	case "new":
		return cmdAddrNew()
	case "list":
		return cmdAddrList()
	case "delete":
		return cmdAddrDelete()
	case "update":
		return cmdAddrUpdate()
	default:
		return errors.New("invalid subcommand")
	}
}

func cmdSig() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdSig",
	})
	l.Debug("starting")
	sigFlagSet := flag.NewFlagSet("sig", flag.ExitOnError)
	privkeyPath := sigFlagSet.String("privkey-path", "", "path to the private key")
	privkeyBase64 := sigFlagSet.String("privkey-base64", "", "base64 encoded private key")
	sigFlagSet.Parse(os.Args[2:])
	l.WithFields(log.Fields{
		"privkey-path":   *privkeyPath,
		"privkey-base64": *privkeyBase64,
	}).Debug("parsed flags")
	var privKeyBytes []byte
	if *privkeyPath != "" {
		// read privkey from file
		fd, err := ioutil.ReadFile(*privkeyPath)
		if err != nil {
			return err
		}
		privKeyBytes = fd
	}
	if *privkeyBase64 != "" {
		// decode base64 privkey
		bd, err := base64.StdEncoding.DecodeString(*privkeyBase64)
		if err != nil {
			return err
		}
		privKeyBytes = bd
	}
	if len(privKeyBytes) == 0 {
		return errors.New("privkey is required")
	}
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	fmt.Print(sig)
	return nil
}
