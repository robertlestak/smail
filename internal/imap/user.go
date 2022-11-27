package imap

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"gopkg.in/gomail.v2"

	"github.com/emersion/go-imap/backend"
	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/encrypt"
	"github.com/robertlestak/smail/pkg/smail"
	log "github.com/sirupsen/logrus"
)

type User struct {
	username  string
	Address   string
	password  string
	mailboxes map[string]*Mailbox
}

func removeInlineAttachments(msg []byte) []byte {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "removeInlineAttachments",
	})
	l.Debug("called")
	// remove all attachments from the message
	var newMsg []byte
	for _, line := range strings.Split(string(msg), "\r\n") {
		if strings.HasPrefix(line, "Content-Disposition: attachment") {
			continue
		}
		newMsg = append(newMsg, []byte(line+"\r\n")...)
	}
	return newMsg
}

func MessageToBytes(m *smail.Message) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "MessageToBytes",
	})
	l.Debug("called")
	gm := gomail.NewMessage()
	gm.SetHeader("From", m.Raw.FromAddr)
	gm.SetHeader("To", m.Raw.To...)
	gm.SetHeader("Subject", m.Raw.Subject)
	if len(m.Raw.CC) > 0 {
		gm.SetHeader("CC", m.Raw.CC...)
	}
	if len(m.Raw.BCC) > 0 {
		gm.SetHeader("BCC", m.Raw.BCC...)
	}
	gm.SetBody("text/plain", m.Raw.Body)
	//gm.SetBody("text/html", m.Raw.Body)
	if len(m.Raw.Attachments) > 0 {
		for _, a := range m.Raw.Attachments {
			gm.Attach(a.Name, gomail.SetCopyFunc(func(w io.Writer) error {
				_, err := w.Write(a.Data)
				return err
			}))
		}
	}
	var bb []byte
	s := gomail.SendFunc(func(from string, to []string, msg io.WriterTo) error {
		l.Debug("sending message")
		l.Debug("from: ", from)
		l.Debug("to: ", to)
		var b bytes.Buffer
		if _, err := msg.WriteTo(&b); err != nil {
			return err
		}
		bb = b.Bytes()
		l.Debug("message: ", b.String())
		return nil
	})
	if err := gomail.Send(s, gm); err != nil {
		return nil, err
	}
	return bb, nil
}

func (u *User) GetSmailMessages(page, pageSize int) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "GetSmailMessages",
	})
	l.Debug("called")
	sig, err := encrypt.NewSig(PrivateKeyBytes)
	if err != nil {
		return err
	}
	var server string
	if u.Address == "" {
		return errors.New("no address")
	}
	if UpstreamServerAddr == "" {
		s, err := smail.EndpointFromAddr(u.Address, false)
		if err != nil {
			return err
		}
		server = s
	} else {
		server = fmt.Sprintf("%s://%s", UpstreamServerProto, UpstreamServerAddr)
	}
	l.WithFields(log.Fields{
		"server": server,
	}).Debug("using server")
	// get messages
	messages, err := smail.GetMessages(server, address.AddressID(u.Address), sig, page, pageSize)
	if err != nil {
		return err
	}
	for _, m := range messages {
		// decrypt message
		if err := m.Decrypt(PrivateKeyBytes); err != nil {
			return err
		}
	}
	// order messages by raw time
	sort.Slice(messages, func(i, j int) bool {
		return messages[i].Raw.Time.After(messages[j].Raw.Time)
	})
	nms := make(map[string][]*Message)
	// convert to imap messages
	mbNexts := make(map[string]uint32)
	for k, m := range u.mailboxes {
		mbNexts[k] = m.uidNext()
	}
	for _, m := range messages {
		var thisuid uint32
		if _, ok := u.mailboxes[m.Raw.Mailbox]; !ok {
			u.mailboxes[m.Raw.Mailbox] = &Mailbox{
				//Subscribed: true,
				Messages: []*Message{},
				name:     m.Raw.Mailbox,
				user:     u,
			}
		}
		for _, v := range u.mailboxes[m.Raw.Mailbox].Messages {
			if v.ID == m.ID {
				thisuid = v.Uid
				break
			}
		}
		if thisuid == 0 {
			thisuid = mbNexts[m.Raw.Mailbox]
			mbNexts[m.Raw.Mailbox]++
		}
		l.WithFields(log.Fields{
			"uid": thisuid,
		}).Debug("thisuid uid")
		//var bb []byte
		//bbb := removeInlineAttachments([]byte(body))
		bb, err := MessageToBytes(m)
		if err != nil {
			return err
		}
		l.WithFields(log.Fields{
			"len": len(bb),
			"bb":  string(bb),
		}).Debug("len bb")
		nm := &Message{
			ID:    m.ID,
			Uid:   thisuid,
			Date:  m.Raw.Time,
			Size:  uint32(len(bb)),
			Flags: m.Raw.Flags,
			Body:  bb,
		}
		// add to INBOX mailbox if not already there
		if _, ok := u.mailboxes[m.Raw.Mailbox]; !ok {
			l.Debugf("creating %s mailbox", m.Raw.Mailbox)
			u.mailboxes[m.Raw.Mailbox] = &Mailbox{
				Subscribed: true,
				Messages:   []*Message{},
				name:       m.Raw.Mailbox,
				user:       u,
			}
		}
		l.WithFields(log.Fields{
			"uid": nm.Uid,
		}).Debugf("adding message to %s", m.Raw.Mailbox)
		nms[m.Raw.Mailbox] = append(nms[m.Raw.Mailbox], nm)
	}
	for k, v := range nms {
		l.WithFields(log.Fields{
			"mailbox": k,
		}).Debugf("adding %d messages", len(v))
		u.mailboxes[k].Messages = v
	}
	return nil
}

func (u *User) Username() string {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Username",
	})
	l.Debug("called")
	return u.username
}

func (u *User) ListMailboxes(subscribed bool) (mailboxes []backend.Mailbox, err error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "ListMailboxes",
	})
	l.Debug("called")
	for _, mailbox := range u.mailboxes {
		if subscribed && !mailbox.Subscribed {
			continue
		}

		mailboxes = append(mailboxes, mailbox)
	}
	return
}

func (u *User) GetMailbox(name string) (mailbox backend.Mailbox, err error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "GetMailbox",
	})
	l.Debug("called")
	mailbox, ok := u.mailboxes[name]
	if !ok {
		err = errors.New("No such mailbox")
	}
	if err := u.GetSmailMessages(0, 100); err != nil {
		return nil, err
	}
	return
}

func (u *User) CreateMailbox(name string) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "CreateMailbox",
	})
	l.Debug("called")
	if _, ok := u.mailboxes[name]; ok {
		return errors.New("Mailbox already exists")
	}

	u.mailboxes[name] = &Mailbox{name: name, user: u}
	return nil
}

func (u *User) DeleteMailbox(name string) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "DeleteMailbox",
	})
	l.Debug("called")
	if name == "INBOX" {
		return errors.New("Cannot delete INBOX")
	}
	if _, ok := u.mailboxes[name]; !ok {
		return errors.New("No such mailbox")
	}

	delete(u.mailboxes, name)
	return nil
}

func (u *User) RenameMailbox(existingName, newName string) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "RenameMailbox",
	})
	l.Debug("called")
	mbox, ok := u.mailboxes[existingName]
	if !ok {
		return errors.New("No such mailbox")
	}

	u.mailboxes[newName] = &Mailbox{
		name:     newName,
		Messages: mbox.Messages,
		user:     u,
	}

	mbox.Messages = nil

	if existingName != "INBOX" {
		delete(u.mailboxes, existingName)
	}

	return nil
}

func (u *User) Logout() error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Logout",
	})
	l.Debug("called")
	return nil
}
