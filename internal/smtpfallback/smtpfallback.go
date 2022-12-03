package smtpfallback

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/robertlestak/smail/internal/utils"
	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/encrypt"
	log "github.com/sirupsen/logrus"
	"gopkg.in/gomail.v2"
)

var (
	Cfg     *Config
	Enabled bool
)

type Config struct {
	Host          string `json:"host"`
	Port          int    `json:"port"`
	User          string `json:"user"`
	Pass          string `json:"pass"`
	TlsEnable     bool   `json:"tls_enable"`
	TlsSkipVerify bool   `json:"tls_skip_verify"`
	TlsCACert     string `json:"tls_ca_cert"`
	TlsCert       string `json:"tls_cert"`
	TlsKey        string `json:"tls_key"`
	Encrypt       bool   `json:"encrypt"`
	KeyDir        string `json:"key_dir"`
}

type Email struct {
	From    string
	To      []string
	Subject string
	Body    string
	Error   error
}

func NewConfig(host string, port int, username string, password string) *Config {
	c := &Config{
		Host: host,
		Port: port,
		User: username,
		Pass: password,
	}
	Cfg = c
	return c
}

func (e *Email) Validate() error {
	l := log.WithFields(log.Fields{
		"action":  "Email Validate",
		"to":      e.To,
		"from":    e.From,
		"subject": e.Subject,
	})
	l.Debug("Validating email")
	if e.From == "" {
		l.Printf("Email validation error=%v", "From is empty")
		return fmt.Errorf("No From address")
	}
	if e.Subject == "" {
		l.Printf("Email validation error=%v", "Subject is empty")
		return fmt.Errorf("No Subject")
	}
	if e.Body == "" {
		l.Printf("Email validation error=%v", "Body is empty")
		return fmt.Errorf("No Body")
	}
	if len(e.To) == 0 {
		l.Printf("Email validation error=%v", "To is empty")
		return fmt.Errorf("No To address")
	}
	return nil
}

func (e *Email) Send() error {
	l := log.WithFields(log.Fields{
		"action":  "SendEmail",
		"to":      e.To,
		"from":    e.From,
		"subject": e.Subject,
	})
	l.Debug("Sending email")
	verr := e.Validate()
	if verr != nil {
		l.Errorf("Email validation error=%v", verr)
		return verr
	}
	m := gomail.NewMessage()
	m.SetHeader("From", e.From)
	m.SetHeader("To", e.To...)
	m.SetHeader("Subject", e.Subject)
	m.SetBody("text/html", e.Body)
	if Cfg.Pass == "" {
		Cfg.User = ""
	}
	d := gomail.NewDialer(
		Cfg.Host,
		Cfg.Port,
		Cfg.User,
		Cfg.Pass,
	)
	c, err := utils.TlsConfig(
		&Cfg.TlsEnable,
		&Cfg.TlsSkipVerify,
		&Cfg.TlsCACert,
		&Cfg.TlsCert,
		&Cfg.TlsKey,
	)
	if err != nil {
		l.Errorf("TLS config error=%v", err)
		return err
	}
	d.TLSConfig = c
	if err := d.DialAndSend(m); err != nil {
		l.Printf("d.DialAndSend error=%v", err)
		return err
	}
	l.Debug("Email sent")
	return nil
}

func InitKeyDir() error {
	l := log.WithFields(log.Fields{
		"action":  "InitKeyDir",
		"dir":     Cfg.KeyDir,
		"encrypt": Cfg.Encrypt,
	})
	l.Debug("Initializing key directory")
	if Cfg.KeyDir == "" || !Cfg.Encrypt {
		l.Debug("Key directory not set or encryption disabled")
		return nil
	}
	l.Debugf("Key directory=%v", Cfg.KeyDir)
	if _, err := os.Stat(Cfg.KeyDir); os.IsNotExist(err) {
		l.Debugf("Key directory does not exist, creating=%v", Cfg.KeyDir)
		err = os.MkdirAll(Cfg.KeyDir, 0700)
		if err != nil {
			l.Errorf("Error creating key directory=%v", err)
			return err
		}
	}
	l.Debug("Key directory initialized")
	return nil
}

func LocalPublicKeyForRemoteAddress(remoteAddr string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"action": "LocalPublicKeyForRemoteAddress",
		"remote": remoteAddr,
	})
	l.Debug("Getting local public key for remote address")
	if Cfg.KeyDir == "" || !Cfg.Encrypt {
		l.Debug("No keydir or encryption disabled")
		return nil, nil
	}
	id := address.AddressID(remoteAddr)
	if id == "" {
		l.Debug("No address ID")
		return nil, nil
	}
	dir := Cfg.KeyDir + "/" + id
	l = l.WithField("dir", dir)
	l.Debug("Checking for keydir")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		// No keydir for this address, create
		l.Debug("Creating keydir")
		err = os.MkdirAll(dir, 0700)
		if err != nil {
			l.Errorf("Error creating keydir=%v", err)
			return nil, err
		}
	}
	l.Debug("Getting public key")
	fn := dir + "/public.pem"
	if _, err := os.Stat(fn); os.IsNotExist(err) {
		l.Debug("Public key does not exist, creating")
		priv, pub, err := encrypt.GenerateRSAKeyPair()
		if err != nil {
			l.Errorf("Error generating keypair=%v", err)
			return nil, err
		}
		privfn := dir + "/private.pem"
		l = l.WithField("privfn", privfn)
		l.Debug("Writing private key")
		if err := ioutil.WriteFile(privfn, priv, 0600); err != nil {
			l.Errorf("Error writing private key=%v", err)
			return nil, err
		}
		l = l.WithField("pubfn", fn)
		l.Debug("Writing public key")
		if err := ioutil.WriteFile(fn, pub, 0600); err != nil {
			l.Errorf("Error writing public key=%v", err)
			return nil, err
		}
		return pub, nil
	}
	l.Debug("Reading public key")
	pub, err := ioutil.ReadFile(fn)
	if err != nil {
		l.Errorf("Error reading public key=%v", err)
		return nil, err
	}
	return pub, nil
}
