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

	"github.com/robertlestak/smail/internal/smtpfallback"
	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/encrypt"
	"github.com/robertlestak/smail/pkg/smail"
	log "github.com/sirupsen/logrus"
)

func cmdMsgSend() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgSend",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("send", flag.ExitOnError)
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
	smtpFallback := msgFlagSet.Bool("smtp-fallback", false, "fallback to SMTP if recipient does not support smail")
	smtpFallbackEncrypt := msgFlagSet.Bool("smtp-fallback-encrypt", true, "encrypt SMTP fallback message")
	smtpFallbackHost := msgFlagSet.String("smtp-fallback-host", "", "host to fallback to if recipient does not support smail")
	smtpFallbackPort := msgFlagSet.Int("smtp-fallback-port", 25, "port to fallback to if recipient does not support smail")
	smtpFallbackUser := msgFlagSet.String("smtp-fallback-user", "", "username to use for fallback SMTP")
	smtpFallbackPass := msgFlagSet.String("smtp-fallback-pass", "", "password to use for fallback SMTP")
	smtpFallbackKeyDir := msgFlagSet.String("smtp-fallback-key-dir", "", "directory to store keys for fallback SMTP")
	smtpFallbackTlsEnable := msgFlagSet.Bool("smtp-fallback-tls", false, "enable TLS for fallback SMTP")
	smtpFallbackTlsSkipVerify := msgFlagSet.Bool("smtp-fallback-tls-skip-verify", false, "skip TLS verification for fallback SMTP")
	smtpFallbackTlsCaCertPath := msgFlagSet.String("smtp-fallback-tls-ca-cert-path", "", "path to CA certificate for fallback SMTP")
	smtpFallbackTlsCertPath := msgFlagSet.String("smtp-fallback-tls-cert-path", "", "path to certificate for fallback SMTP")
	smtpFallbackTlsKeyPath := msgFlagSet.String("smtp-fallback-tls-key-path", "", "path to key for fallback SMTP")
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
	if *smtpFallback {
		smtpfallback.Enabled = true
		smtpfallback.Cfg = &smtpfallback.Config{
			Host:          *smtpFallbackHost,
			Port:          *smtpFallbackPort,
			User:          *smtpFallbackUser,
			Pass:          *smtpFallbackPass,
			TlsEnable:     *smtpFallbackTlsEnable,
			TlsSkipVerify: *smtpFallbackTlsSkipVerify,
			TlsCACert:     *smtpFallbackTlsCaCertPath,
			TlsCert:       *smtpFallbackTlsCertPath,
			TlsKey:        *smtpFallbackTlsKeyPath,
			Encrypt:       *smtpFallbackEncrypt,
			KeyDir:        *smtpFallbackKeyDir,
		}
		if err := smtpfallback.InitKeyDir(); err != nil {
			return err
		}
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
		Time:        time.Now(),
	}
	if err := rm.Send(*useDOH); err != nil {
		return err
	}
	return nil
}

func messageDecryptWorker(jobs <-chan *smail.Message, results chan<- error, privKey []byte) {
	for j := range jobs {
		// decrypt the message
		err := j.Decrypt(privKey)
		if err != nil {
			log.WithFields(log.Fields{
				"app": "cli",
				"fn":  "messageDecryptWorker",
			}).Error(err)
			results <- err
			continue
		}
		results <- nil
	}
}

func cmdMsgList() error {
	l := log.WithFields(log.Fields{
		"app": "cli",
		"fn":  "cmdMsgList",
	})
	l.Debug("starting")
	msgFlagSet := flag.NewFlagSet("list", flag.ExitOnError)
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
		workers := 10
		if len(messages) < workers {
			workers = len(messages)
		}
		jobs := make(chan *smail.Message, workers)
		results := make(chan error, workers)
		for w := 1; w <= workers; w++ {
			go messageDecryptWorker(jobs, results, privKeyBytes)
		}
		for _, m := range messages {
			// decrypt message
			jobs <- m
		}
		close(jobs)
		for a := 1; a <= len(messages); a++ {
			if err := <-results; err != nil {
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
	case "send":
		return cmdMsgSend()
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
