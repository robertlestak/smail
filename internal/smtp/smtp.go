package smtp

import (
	"bytes"
	"errors"
	"io"
	"io/ioutil"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/jhillyerd/enmime"
	"github.com/robertlestak/smail/internal/utils"
	"github.com/robertlestak/smail/pkg/smail"
	log "github.com/sirupsen/logrus"
)

var (
	AllowAnonymous = false
	DefaultUser    string
	DefaultPass    string
)

// The Backend implements SMTP server methods.
type Backend struct{}

// Login handles a login command with username and password.
func (bkd *Backend) Login(state *smtp.ConnectionState, username, password string) (smtp.Session, error) {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Login",
	})
	l.Debug("Login attempt")
	if DefaultUser == "" || DefaultPass == "" {
		l.Debug("No default user or pass set")
		return nil, errors.New("No user or password set")
	}
	if username != DefaultUser || password != DefaultPass {
		l.Debug("Invalid username or password")
		return nil, errors.New("invalid username or password")
	}
	l.Debug("Login successful")
	return &Session{}, nil
}

// AnonymousLogin requires clients to authenticate using SMTP AUTH before sending emails
func (bkd *Backend) AnonymousLogin(state *smtp.ConnectionState) (smtp.Session, error) {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "AnonymousLogin",
	})
	l.Debug("Anonymous login attempt")
	//return nil, smtp.ErrAuthRequired
	if AllowAnonymous {
		l.Debug("Anonymous login allowed")
		return &Session{}, nil
	}
	l.Debug("Anonymous login not allowed")
	return nil, smtp.ErrAuthRequired
}

// A Session is returned after successful login.
type Session struct {
	From    string
	To      []string
	Content []byte
}

func (s *Session) Mail(from string, opts smtp.MailOptions) error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Mail",
	})
	l.Debug("Mail from:", from)
	s.From = from
	return nil
}

func (s *Session) Rcpt(to string) error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Rcpt",
	})
	l.Debug("Rcpt to:", to)
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
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Data",
	})
	l.Debug("Data")
	if b, err := ioutil.ReadAll(r); err != nil {
		l.Error("Error reading data:", err)
		return err
	} else {
		l.Debug("Data read")
		s.Content = b
	}
	subject, body, attachments, emailTime, err := parseEmailContent(s.Content)
	if err != nil {
		l.Debugf("Error parsing email content:", err)
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
	l.Debug("Sending email to queue")
	if err := rm.Send(false); err != nil {
		l.Error("Error sending email to queue:", err)
		return err
	}
	l.Debug("Email sent to queue")
	return nil
}

func (s *Session) Reset() {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Reset",
	})
	l.Debug("Reset")
	s.From = ""
	s.To = []string{}
	s.Content = []byte{}
}

func (s *Session) Logout() error {
	l := log.WithFields(log.Fields{
		"app": "smtp",
		"fn":  "Logout",
	})
	l.Debug("Logout")
	return nil
}

func Start(domain string, port string, tlsCAPath string, tlsCrtPath string, tlsKeyPath string, allowInsecureAuth bool, allowAnon bool, username string, password string) error {
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
	AllowAnonymous = allowAnon
	DefaultUser = username
	DefaultPass = password
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
		l.Error("Error starting server:", err)
		return err
	}
	return nil
}
