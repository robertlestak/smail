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

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func messageDecryptWorker(jobs <-chan *smail.Message, results chan<- error, privKey []byte) {
	for j := range jobs {
		// decrypt the message
		err := j.Decrypt(privKey)
		if err != nil {
			log.WithFields(log.Fields{
				"app": "imap",
				"fn":  "messageDecryptWorker",
			}).Error(err)
			results <- err
			continue
		}
		results <- nil
	}
}

func (u *User) GetNewMailMessages(existing []string) error {
	l := log.WithFields(log.Fields{
		"package":  "imap",
		"fn":       "GetNewMailMessages",
		"existing": existing,
	})
	l.Debug("called")
	// get all message keys from server
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
	messages, err := smail.GetMessageKeys(server, address.AddressID(u.Address), sig, -1, 100)
	if err != nil {
		return err
	}
	l.WithFields(log.Fields{
		"messages": messages,
	}).Debug("got messages")
	// get the ids which are not in the existing list
	var newIDs []string
	for _, m := range messages {
		if !contains(existing, m) {
			newIDs = append(newIDs, m)
		}
	}
	l.WithFields(log.Fields{
		"newIDs": newIDs,
	}).Debug("got newIDs")
	// get the new messages
	if len(newIDs) == 0 {
		l.Debug("no new messages")
		return nil
	}
	newMessages, err := smail.GetMessagesByIDs(server, address.AddressID(u.Address), sig, newIDs)
	if err != nil {
		return err
	}
	if len(newMessages) == 0 {
		l.Debug("no new messages")
		return nil
	}
	// decrypt the messages
	workers := 10
	if len(newMessages) < workers {
		workers = len(newMessages)
	}
	jobs := make(chan *smail.Message, len(newMessages))
	results := make(chan error, len(newMessages))
	for w := 1; w <= workers; w++ {
		go messageDecryptWorker(jobs, results, PrivateKeyBytes)
	}
	for _, m := range newMessages {
		jobs <- m
	}
	close(jobs)
	for a := 1; a <= len(newMessages); a++ {
		if err := <-results; err != nil {
			return err
		}
	}
	// add the new messages to the inbox
	if err := u.smailToImap(newMessages); err != nil {
		return err
	}
	return nil
}

func (u *User) smailToImap(messages []*smail.Message) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "smailToImap",
	})
	l.Debug("called")
	nms := make(map[string][]*Message)
	// convert to imap messages
	mbNexts := make(map[string]uint32)
	for k, m := range u.mailboxes {
		mbNexts[k] = m.uidNext()
	}
	for _, m := range messages {
		var thisuid uint32
		if u == nil || u.mailboxes == nil || len(u.mailboxes) == 0 {
			return errors.New("no mailboxes")
		}
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
		u.mailboxes[k].Messages = append(u.mailboxes[k].Messages, v...)
	}
	return nil
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
	if err := u.smailToImap(messages); err != nil {
		return err
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

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func (mbox *Mailbox) CurrentMessageIDs() ([]string, error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "CurrentMessageIDs",
	})
	l.Debug("called")
	var ids []string
	if mbox == nil || mbox.Messages == nil {
		return ids, nil
	}
	for _, m := range mbox.Messages {
		// add to ids if not already there
		if !stringInSlice(m.ID, ids) {
			ids = append(ids, m.ID)
		}
	}
	l.WithFields(log.Fields{
		"ids": ids,
		"len": len(ids),
	}).Debug("ids")
	return ids, nil
}

func (u *User) CurrentMessageIDs() ([]string, error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "CurrentMessageIDs",
	})
	l.Debug("called")
	var ids []string
	if u.mailboxes == nil || len(u.mailboxes) == 0 {
		return ids, nil
	}
	for _, m := range u.mailboxes {
		for _, mm := range m.Messages {
			// add to ids if not already there
			if !stringInSlice(mm.ID, ids) {
				ids = append(ids, mm.ID)
			}
		}
	}
	l.WithFields(log.Fields{
		"ids": ids,
		"len": len(ids),
	}).Debug("ids")
	return ids, nil
}

func (u *User) GetMailbox(name string) (mailbox backend.Mailbox, err error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "GetMailbox",
		"name":    name,
	})
	l.Debug("called")
	mailbox, ok := u.mailboxes[name]
	if !ok {
		err = errors.New("No such mailbox")
		return nil, err
	}
	mex, err := u.CurrentMessageIDs()
	if err != nil {
		return nil, err
	}
	l.WithFields(log.Fields{
		"mex": mex,
	}).Debug("mex")
	if err := u.GetNewMailMessages(mex); err != nil {
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
