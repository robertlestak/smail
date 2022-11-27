package cli

import (
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/encrypt"
	"github.com/robertlestak/smail/pkg/smail"
	log "github.com/sirupsen/logrus"
)

func cmdMsgNew() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgNew",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	fromAddr := msgFlagSet.String("from", "", "from address")
	toStr := msgFlagSet.String("to", "", "to addresses")
	ccStr := msgFlagSet.String("cc", "", "cc addresses")
	bccStr := msgFlagSet.String("bcc", "", "bcc addresses")
	subject := msgFlagSet.String("subject", "", "subject")
	attachments := msgFlagSet.String("attachments", "", "attachments")
	body := msgFlagSet.String("body", "", "body")
	privkeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privkeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"from":           *fromAddr,
		"to":             *toStr,
		"cc":             *ccStr,
		"bcc":            *bccStr,
		"subject":        *subject,
		"body":           *body,
		"privkey-path":   *privkeyPath,
		"privkey-base64": *privkeyBase64,
		"attachments":    *attachments,
	}).Debug("parsed flags")
	if *fromAddr == "" {
		return errors.New("from is required")
	}
	if *toStr == "" {
		return errors.New("to is required")
	}
	if *subject == "" {
		return errors.New("subject is required")
	}
	if *body == "" {
		return errors.New("body is required")
	}
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
	var to []string
	var cc []string
	var bcc []string
	if *toStr != "" {
		to = strings.Split(*toStr, ",")
	}
	if *ccStr != "" {
		cc = strings.Split(*ccStr, ",")
	}
	if *bccStr != "" {
		bcc = strings.Split(*bccStr, ",")
	}
	var attachmentsList []string
	var attach []smail.Attachment
	if *attachments != "" {
		attachmentsList = strings.Split(*attachments, ",")
		for _, a := range attachmentsList {
			fd, err := ioutil.ReadFile(a)
			if err != nil {
				return err
			}
			attach = append(attach, smail.Attachment{
				Name: path.Base(a),
				Data: fd,
			})
		}
	}
	rm := &smail.RawMessage{
		FromAddr:    *fromAddr,
		Subject:     *subject,
		Body:        *body,
		To:          to,
		CC:          cc,
		BCC:         bcc,
		Attachments: attach,
		Mailbox:     "INBOX",
		Time:        time.Now(),
	}
	if err := rm.Send(*useDOH); err != nil {
		return err
	}
	return nil
}

func cmdMsgList() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgList",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	addr := msgFlagSet.String("addr", "", "address")
	server := msgFlagSet.String("server", "", "server")
	serverProto := msgFlagSet.String("server-proto", "https", "server protocol")
	privateKeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	decrypt := msgFlagSet.Bool("decrypt", false, "decrypt messages")
	page := msgFlagSet.Int("page", 0, "page")
	pageSize := msgFlagSet.Int("page-size", 10, "page size")
	output := msgFlagSet.String("output", "json", "output format")
	outputPath := msgFlagSet.String("output-path", "-", "output path")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"addr":           *addr,
		"server":         *server,
		"privkey-path":   *privateKeyPath,
		"privkey-base64": *privateKeyBase64,
	}).Debug("parsed flags")
	if *addr == "" {
		return errors.New("addr is required")
	}
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
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		s, err := smail.EndpointFromAddr(*addr, *useDOH)
		if err != nil {
			return err
		}
		*server = s
	} else {
		*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	}
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	// get messages
	messages, err := smail.GetMessages(*server, address.AddressID(*addr), sig, *page, *pageSize)
	if err != nil {
		return err
	}
	if *decrypt {
		for _, m := range messages {
			// decrypt message
			if err := m.Decrypt(privKeyBytes); err != nil {
				return err
			}
		}
		// order messages by raw time
		sort.Slice(messages, func(i, j int) bool {
			return messages[i].Raw.Time.After(messages[j].Raw.Time)
		})
	}
	return outputData(messages, *output, *outputPath)
}

func cmdMsgListKeys() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgListKeys",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	addr := msgFlagSet.String("addr", "", "address")
	server := msgFlagSet.String("server", "", "server")
	serverProto := msgFlagSet.String("server-proto", "https", "server protocol")
	privateKeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	page := msgFlagSet.Int("page", 0, "page")
	pageSize := msgFlagSet.Int("page-size", 10, "page size")
	output := msgFlagSet.String("output", "json", "output format")
	outputPath := msgFlagSet.String("output-path", "-", "output path")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"addr":           *addr,
		"server":         *server,
		"privkey-path":   *privateKeyPath,
		"privkey-base64": *privateKeyBase64,
	}).Debug("parsed flags")
	if *addr == "" {
		return errors.New("addr is required")
	}
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
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		s, err := smail.EndpointFromAddr(*addr, *useDOH)
		if err != nil {
			return err
		}
		*server = s
	} else {
		*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	}
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	// get messages
	messages, err := smail.GetMessageKeys(*server, address.AddressID(*addr), sig, *page, *pageSize)
	if err != nil {
		return err
	}
	return outputData(messages, *output, *outputPath)
}

func cmdMsgDelete() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgDelete",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	addr := msgFlagSet.String("addr", "", "address")
	id := msgFlagSet.String("id", "", "message id")
	server := msgFlagSet.String("server", "", "server")
	serverProto := msgFlagSet.String("server-proto", "https", "server protocol")
	privateKeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"addr":           *addr,
		"id":             *id,
		"privkey-path":   *privateKeyPath,
		"privkey-base64": *privateKeyBase64,
	}).Debug("parsed flags")
	if *addr == "" {
		return errors.New("addr is required")
	}
	if *id == "" {
		return errors.New("id is required")
	}
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
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		s, err := smail.EndpointFromAddr(*addr, *useDOH)
		if err != nil {
			return err
		}
		*server = s
	} else {
		*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	}
	// delete message
	if err := smail.DeleteMessage(*server, address.AddressID(*addr), *id, sig); err != nil {
		return err
	}
	return nil
}

func cmdMsgGet() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgGet",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	addr := msgFlagSet.String("addr", "", "address")
	id := msgFlagSet.String("id", "", "message id")
	server := msgFlagSet.String("server", "", "server")
	serverProto := msgFlagSet.String("server-proto", "https", "server protocol")
	privateKeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	output := msgFlagSet.String("output", "json", "output format")
	attachmentDir := msgFlagSet.String("attachment-dir", "", "attachment directory")
	outputPath := msgFlagSet.String("output-path", "-", "output path")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"addr":           *addr,
		"id":             *id,
		"privkey-path":   *privateKeyPath,
		"privkey-base64": *privateKeyBase64,
	}).Debug("parsed flags")
	if *addr == "" {
		return errors.New("addr is required")
	}
	if *id == "" {
		return errors.New("id is required")
	}
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
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		s, err := smail.EndpointFromAddr(*addr, *useDOH)
		if err != nil {
			return err
		}
		*server = s
	} else {
		*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	}
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	// get message
	m, err := smail.GetMessage(*server, address.AddressID(*addr), *id, sig)
	if err != nil {
		return err
	}
	// decrypt message
	if err := m.Decrypt(privKeyBytes); err != nil {
		return err
	}
	if *attachmentDir != "" {
		if _, err := os.Stat(*attachmentDir); os.IsNotExist(err) {
			if err := os.MkdirAll(*attachmentDir, 0700); err != nil {
				return err
			}
		}
		// save attachments
		for _, a := range m.Raw.Attachments {
			if err := ioutil.WriteFile(filepath.Join(*attachmentDir, a.Name), a.Data, 0644); err != nil {
				return err
			}
		}
	}
	return outputData(m, *output, *outputPath)
}

func cmdMsgUpdateMailbox() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgUpdateMailbox",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	addr := msgFlagSet.String("addr", "", "address")
	id := msgFlagSet.String("id", "", "message id")
	server := msgFlagSet.String("server", "", "server")
	mailbox := msgFlagSet.String("mailbox", "", "mailbox")
	serverProto := msgFlagSet.String("server-proto", "https", "server protocol")
	privateKeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"addr":           *addr,
		"privkey-path":   *privateKeyPath,
		"privkey-base64": *privateKeyBase64,
	}).Debug("parsed flags")
	if *addr == "" {
		return errors.New("addr is required")
	}
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
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		s, err := smail.EndpointFromAddr(*addr, *useDOH)
		if err != nil {
			return err
		}
		*server = s
	} else {
		*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	}
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	// get mailbox
	m, err := smail.GetMessage(*server, address.AddressID(*addr), *id, sig)
	if err != nil {
		return err
	}
	// decrypt message
	if err := m.Decrypt(privKeyBytes); err != nil {
		return err
	}
	// update mailbox
	m.Raw.Mailbox = *mailbox
	// encrypt message
	priv, err := encrypt.BytesToPrivKey(privKeyBytes)
	if err != nil {
		return err
	}
	enc, err := m.Raw.Encrypt(encrypt.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		return err
	}
	m.EncryptedMessage = enc
	// update message
	aid := address.AddressID(*addr)
	if err := smail.UpdateRemoteMessage(*server, aid, *id, m, sig); err != nil {
		return err
	}
	return nil
}

func cmdMsgUpdateFlags() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgUpdateFlags",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("msg", flag.ExitOnError)
	addr := msgFlagSet.String("addr", "", "address")
	id := msgFlagSet.String("id", "", "message id")
	server := msgFlagSet.String("server", "", "server")
	flags := msgFlagSet.String("flags", "", "flags")
	serverProto := msgFlagSet.String("server-proto", "https", "server protocol")
	privateKeyPath := msgFlagSet.String("privkey-path", "", "path to the private key")
	privateKeyBase64 := msgFlagSet.String("privkey-base64", "", "base64 encoded private key")
	useDOH := msgFlagSet.Bool("use-doh", false, "use DNS over HTTPS")
	msgFlagSet.Parse(os.Args[3:])
	l.WithFields(log.Fields{
		"addr":           *addr,
		"privkey-path":   *privateKeyPath,
		"privkey-base64": *privateKeyBase64,
	}).Debug("parsed flags")
	if *addr == "" {
		return errors.New("addr is required")
	}
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
	sig, err := encrypt.NewSig(privKeyBytes)
	if err != nil {
		return err
	}
	if *server == "" {
		s, err := smail.EndpointFromAddr(*addr, *useDOH)
		if err != nil {
			return err
		}
		*server = s
	} else {
		*server = fmt.Sprintf("%s://%s", *serverProto, *server)
	}
	l.WithFields(log.Fields{
		"server": *server,
	}).Debug("using server")
	// get mailbox
	m, err := smail.GetMessage(*server, address.AddressID(*addr), *id, sig)
	if err != nil {
		return err
	}
	// decrypt message
	if err := m.Decrypt(privKeyBytes); err != nil {
		return err
	}
	// update flags
	var flagsArr []string
	if *flags != "" {
		flagsArr = strings.Split(*flags, ",")
		// remove empty flags
		for i := 0; i < len(flagsArr); i++ {
			if flagsArr[i] == "" {
				flagsArr = append(flagsArr[:i], flagsArr[i+1:]...)
				i--
			}
		}
	}
	m.Raw.Flags = flagsArr
	// encrypt message
	priv, err := encrypt.BytesToPrivKey(privKeyBytes)
	if err != nil {
		return err
	}
	enc, err := m.Raw.Encrypt(encrypt.PubKeyBytes(&priv.PublicKey))
	if err != nil {
		return err
	}
	m.EncryptedMessage = enc
	// update message
	aid := address.AddressID(*addr)
	if err := smail.UpdateRemoteMessage(*server, aid, *id, m, sig); err != nil {
		return err
	}
	return nil
}

func cmdMsg() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsg",
	})
	l.Debug("starting")
	// subcommands
	// msg new
	// msg list
	// msg delete
	var arg string
	if len(os.Args) > 2 {
		arg = os.Args[2]
	}
	switch arg {
	case "new":
		return cmdMsgNew()
	case "list":
		return cmdMsgList()
	case "list-keys":
		return cmdMsgListKeys()
	case "delete":
		return cmdMsgDelete()
	case "get":
		return cmdMsgGet()
	case "update-mailbox":
		return cmdMsgUpdateMailbox()
	case "update-flags":
		return cmdMsgUpdateFlags()
	default:
		return errors.New("invalid subcommand")
	}
}
