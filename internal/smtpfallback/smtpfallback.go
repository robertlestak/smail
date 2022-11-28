package smtpfallback

import (
	"fmt"

	"github.com/robertlestak/smail/internal/utils"
	log "github.com/sirupsen/logrus"
	"gopkg.in/gomail.v2"
)

var (
	Enabled bool
	Cfg     *Config
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
