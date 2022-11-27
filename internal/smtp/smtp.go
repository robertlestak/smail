package smtp

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/jhillyerd/enmime"
	"github.com/robertlestak/smail/internal/utils"
	"github.com/robertlestak/smail/pkg/smail"
	log "github.com/sirupsen/logrus"
)

// The Backend implements SMTP server methods.
type Backend struct{}

// Login handles a login command with username and password.
func (bkd *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	if username != os.Getenv("SMTP_USER") || password != os.Getenv("SMTP_PASS") {
		return nil, errors.New("invalid username or password")
	}
	return &Session{}, nil
}

// AnonymousLogin requires clients to authenticate using SMTP AUTH before sending emails
func (bkd *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	//return nil, smtp.ErrAuthRequired
	if os.Getenv("SMTP_ANONYMOUS") == "true" {
		return &Session{}, nil
	}
	return nil, smtp.ErrAuthRequired
}

// A Session is returned after successful login.
type Session struct {
	From    string
	To      []string
	Content []byte
}

func (s *Session) Mail(from string, opts smtp.MailOptions) error {
	s.From = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	s.To = append(s.To, to)
	return nil
}

// parseEmailContent parses the email content and returns the subject, body, attachments,
// and time of the email.
func parseEmailContent(content []byte) (string, string, []smail.Attachment, time.Time, error) {
	l := log.WithField("func", "parseEmailContent")
	l.Debug("Parsing email content")
	var subject, body string
	var attachments []smail.Attachment
	var emailTime time.Time
	// Parse the email content
	env, err := enmime.ReadEnvelope(bytes.NewReader(content))
	if err != nil {
		return subject, body, attachments, emailTime, err
	}
	// Get the email subject
	subject = env.GetHeader("Subject")
	// Get the email body
	body = env.Text
	// if there is html body, use that instead
	if env.HTML != "" {
		body = env.HTML
	}
	l.Debug("Email body:", body)
	// Get the email time
	emailTime, err = env.Date()
	if err != nil {
		return subject, body, attachments, emailTime, err
	}
	// Get the email attachments
	for _, attachment := range env.Attachments {
		attachments = append(attachments, smail.Attachment{
			Name: attachment.FileName,
			Data: attachment.Content,
		})
	}
	for _, attachment := range env.Inlines {
		attachments = append(attachments, smail.Attachment{
			Name: attachment.FileName,
			Data: attachment.Content,
		})
	}
	l.Debug("Email attachments:", attachments)
	return subject, body, attachments, emailTime, nil
}

func (s *Session) Data(r io.Reader) error {
	if b, err := ioutil.ReadAll(r); err != nil {
		return err
	} else {
		s.Content = b
	}
	subject, body, attachments, emailTime, err := parseEmailContent(s.Content)
	if err != nil {
		log.Debugf("Error parsing email content:", err)
	}
	if subject == "" {
		subject = "No Subject"
	}
	if body == "" {
		body = string(s.Content)
	}
	if emailTime.IsZero() {
		emailTime = time.Now()
	}
	rm := &smail.RawMessage{
		FromAddr:    s.From,
		To:          s.To,
		Subject:     subject,
		Body:        body,
		Attachments: attachments,
		Time:        emailTime,
	}
	if err := rm.Send(false); err != nil {
		return err
	}
	return nil
}

func (s *Session) Reset() {
	s.From = ""
	s.To = []string{}
	s.Content = []byte{}
}

func (s *Session) Logout() error {
	return nil
}

func Start(domain string, port string, tlsCAPath string, tlsCrtPath string, tlsKeyPath string, allowInsecureAuth bool) error {
	l := log.WithFields(log.Fields{
		"func": "Start",
		"port": port,
	})
	l.Debug("Starting SMTP server")
	be := &Backend{}

	s := smtp.NewServer(be)

	s.Addr = domain + ":" + port
	s.Domain = domain
	s.ReadTimeout = 30 * time.Second
	s.WriteTimeout = 30 * time.Second
	// max size is 100MB
	s.MaxMessageBytes = 1024 * 1024 * 100
	s.MaxRecipients = 50
	s.AllowInsecureAuth = allowInsecureAuth
	if tlsCrtPath != "" && tlsKeyPath != "" {
		enableTls := true
		tlsInsecure := false
		t, err := utils.TlsConfig(&enableTls, &tlsInsecure, &tlsCAPath, &tlsCrtPath, &tlsKeyPath)
		if err != nil {
			return err
		}
		s.TLSConfig = t
	}
	l.Debug("Starting server at", s.Addr)
	if err := s.ListenAndServe(); err != nil {
		return err
	}
	return nil
}
