package imap

import (
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend/backendutil"
	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/encrypt"
	"github.com/robertlestak/smail/pkg/smail"
	log "github.com/sirupsen/logrus"
)

var Delimiter = "/"

type Mailbox struct {
	Subscribed bool
	Messages   []*Message

	name string
	user *User
}

var (
	SmailMessages []*smail.Message
)

func (mbox *Mailbox) Name() string {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Name",
	})
	l.Debug("called")
	return mbox.name
}

func (mbox *Mailbox) Info() (*imap.MailboxInfo, error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Info",
	})
	l.Debug("called")
	info := &imap.MailboxInfo{
		Delimiter: Delimiter,
		Name:      mbox.name,
	}
	return info, nil
}

func (mbox *Mailbox) uidNext() uint32 {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "uidNext",
	})
	l.Debug("called")
	var uid uint32
	for _, msg := range mbox.Messages {
		if msg.Uid > uid {
			uid = msg.Uid
		}
	}
	uid++
	return uid
}

func (mbox *Mailbox) flags() []string {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "flags",
	})
	l.Debug("called")
	flagsMap := make(map[string]bool)
	for _, msg := range mbox.Messages {
		for _, f := range msg.Flags {
			if !flagsMap[f] {
				flagsMap[f] = true
			}
		}
	}

	var flags []string
	for f := range flagsMap {
		flags = append(flags, f)
	}
	return flags
}

func (mbox *Mailbox) unseenSeqNum() uint32 {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "unseenSeqNum",
	})
	l.Debug("called")
	for i, msg := range mbox.Messages {
		seqNum := uint32(i + 1)

		seen := false
		for _, flag := range msg.Flags {
			if flag == imap.SeenFlag {
				seen = true
				break
			}
		}

		if !seen {
			return seqNum
		}
	}
	return 0
}

func (mbox *Mailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Status",
	})
	l.Debug("called")
	if len(items) == 0 || mbox == nil {
		return nil, nil
	}
	status := imap.NewMailboxStatus(mbox.name, items)
	status.Flags = mbox.flags()
	status.PermanentFlags = []string{"\\*"}
	status.UnseenSeqNum = mbox.unseenSeqNum()

	for _, name := range items {
		switch name {
		case imap.StatusMessages:
			status.Messages = uint32(len(mbox.Messages))
		case imap.StatusUidNext:
			status.UidNext = mbox.uidNext()
		case imap.StatusUidValidity:
			status.UidValidity = 1
		case imap.StatusRecent:
			status.Recent = 0 // TODO
		case imap.StatusUnseen:
			status.Unseen = 0 // TODO
		}
	}
	return status, nil
}

func (mbox *Mailbox) SetSubscribed(subscribed bool) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "SetSubscribed",
	})
	l.Debug("called")
	mbox.Subscribed = subscribed
	return nil
}

func (mbox *Mailbox) Check() error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Check",
	})
	l.Debug("called")
	return nil
}

func (mbox *Mailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "ListMessages",
	})
	l.Debug("called")
	defer close(ch)

	for i, msg := range mbox.Messages {
		seqNum := uint32(i + 1)

		var id uint32
		if uid {
			id = msg.Uid
		} else {
			id = seqNum
		}
		if !seqSet.Contains(id) {
			continue
		}

		m, err := msg.Fetch(seqNum, items)
		if err != nil {
			continue
		}

		ch <- m
	}

	return nil
}

func (mbox *Mailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "SearchMessages",
	})
	l.Debug("called")
	var ids []uint32
	for i, msg := range mbox.Messages {
		seqNum := uint32(i + 1)

		ok, err := msg.Match(seqNum, criteria)
		if err != nil || !ok {
			continue
		}

		var id uint32
		if uid {
			id = msg.Uid
		} else {
			id = seqNum
		}
		ids = append(ids, id)
	}
	return ids, nil
}

func (mbox *Mailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "CreateMessage",
	})
	l.Debug("called")
	if date.IsZero() {
		date = time.Now()
	}

	b, err := ioutil.ReadAll(body)
	if err != nil {
		return err
	}

	mbox.Messages = append(mbox.Messages, &Message{
		Uid:   mbox.uidNext(),
		Date:  date,
		Size:  uint32(len(b)),
		Flags: flags,
		Body:  b,
	})
	return nil
}

func (mbox *Mailbox) updateFlags(id uint32) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "updateFlags",
	})
	l.Debug("called")
	sig, err := encrypt.NewSig(PrivateKeyBytes)
	if err != nil {
		return err
	}
	var server string
	if UpstreamServerAddr == "" {
		s, err := smail.EndpointFromAddr(mbox.user.Address, false)
		if err != nil {
			return err
		}
		server = s
	} else {
		server = fmt.Sprintf("%s://%s", UpstreamServerProto, UpstreamServerAddr)
	}
	var msgId string
	// loop through messages to find the one we want to update
	var msgIndex int
	for i, msg := range mbox.user.mailboxes[mbox.Name()].Messages {
		if msg.Uid == id {
			msgId = msg.ID
			msgIndex = i
			break
		}
	}
	if msgId == "" {
		return fmt.Errorf("no message id")
	}
	// get the message from the upstream server
	aid := address.AddressID(mbox.user.Address)
	m, err := smail.GetMessage(server, aid, msgId, sig)
	if err != nil {
		return err
	}
	// decrypt the message
	err = m.Decrypt(PrivateKeyBytes)
	if err != nil {
		return err
	}
	// update the flags
	m.Raw.Flags = mbox.user.mailboxes[mbox.Name()].Messages[msgIndex].Flags
	l.Debugf("flags: %v", m.Raw.Flags)
	// re-encrypt the message
	var enc []byte
	pk, err := encrypt.BytesToPrivKey(PrivateKeyBytes)
	if err != nil {
		return err
	}
	enc, err = m.Raw.Encrypt(encrypt.PubKeyBytes(&pk.PublicKey))
	if err != nil {
		return err
	}
	m.EncryptedMessage = enc
	// update the message on the upstream server
	err = smail.UpdateRemoteMessage(server, aid, msgId, m, sig)
	if err != nil {
		return err
	}
	return nil
}

func (mbox *Mailbox) updateMailbox(name string, id uint32) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "updateMailbox",
	})
	l.Debug("called")
	sig, err := encrypt.NewSig(PrivateKeyBytes)
	if err != nil {
		return err
	}
	var server string
	if UpstreamServerAddr == "" {
		s, err := smail.EndpointFromAddr(mbox.user.Address, false)
		if err != nil {
			return err
		}
		server = s
	} else {
		server = fmt.Sprintf("%s://%s", UpstreamServerProto, UpstreamServerAddr)
	}
	var msgId string
	// loop through messages to find the one we want to update
	for _, msg := range mbox.user.mailboxes[name].Messages {
		if msg.Uid == id {
			msgId = msg.ID
			break
		}
	}
	if msgId == "" {
		return fmt.Errorf("no message id")
	}
	// get the message from the upstream server
	aid := address.AddressID(mbox.user.Address)
	m, err := smail.GetMessage(server, aid, msgId, sig)
	if err != nil {
		return err
	}
	// decrypt the message
	err = m.Decrypt(PrivateKeyBytes)
	if err != nil {
		return err
	}
	// update the flags
	m.Raw.Mailbox = name
	// re-encrypt the message
	pk, err := encrypt.BytesToPrivKey(PrivateKeyBytes)
	if err != nil {
		return err
	}
	var enc []byte
	enc, err = m.Raw.Encrypt(encrypt.PubKeyBytes(&pk.PublicKey))
	if err != nil {
		return err
	}
	m.EncryptedMessage = enc
	// update the message on the upstream server
	err = smail.UpdateRemoteMessage(server, aid, msgId, m, sig)
	if err != nil {
		return err
	}
	return nil
}

func (mbox *Mailbox) UpdateMessagesFlags(uid bool, seqset *imap.SeqSet, op imap.FlagsOp, flags []string) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "UpdateMessagesFlags",
	})
	l.Debug("called")
	for i, msg := range mbox.Messages {
		var id uint32
		if uid {
			id = msg.Uid
		} else {
			id = uint32(i + 1)
		}
		if !seqset.Contains(id) {
			continue
		}

		msg.Flags = backendutil.UpdateFlags(msg.Flags, op, flags)
		if uid {
			if err := mbox.updateFlags(msg.Uid); err != nil {
				return err
			}
		}
	}

	return nil
}

func (mbox *Mailbox) deleteMessage(id uint32) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "deleteMessage",
		"id":      id,
		"name":    mbox.Name(),
	})
	l.Debug("called")
	sig, err := encrypt.NewSig(PrivateKeyBytes)
	if err != nil {
		return err
	}
	var server string
	if UpstreamServerAddr == "" {
		s, err := smail.EndpointFromAddr(mbox.user.Address, false)
		if err != nil {
			return err
		}
		server = s
	} else {
		server = fmt.Sprintf("%s://%s", UpstreamServerProto, UpstreamServerAddr)
	}
	// delete message
	var msgId string
	// loop through messages to find the one we want to delete
	for _, msg := range mbox.user.mailboxes[mbox.Name()].Messages {
		if msg.Uid == id {
			msgId = msg.ID
			break
		}
	}
	if msgId == "" {
		return fmt.Errorf("no message id")
	}
	addrId := address.AddressID(mbox.user.Address)
	l.WithFields(log.Fields{
		"msgId":  msgId,
		"addr":   mbox.user.Address,
		"addrId": addrId,
	}).Debug("deleting message")
	if err := smail.DeleteMessage(server, addrId, msgId, sig); err != nil {
		return err
	}
	return nil
}

func (mbox *Mailbox) CopyMessages(uid bool, seqset *imap.SeqSet, destName string) error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "CopyMessages",
		"uid":     uid,
		"seqset":  seqset,
		"dest":    destName,
	})
	l.Debug("called")
	if destName == "" {
		return errors.New("Destination mailbox name is empty")
	}
	dest, ok := mbox.user.mailboxes[destName]
	if !ok {
		// create destination mailbox
		dest = &Mailbox{
			user: mbox.user,
			name: destName,
			//Subscribed: true,
		}
	}

	for i, msg := range mbox.Messages {
		var id uint32
		if uid {
			id = msg.Uid
		} else {
			id = uint32(i + 1)
		}
		if !seqset.Contains(id) {
			continue
		}
		msgCopy := *msg
		msgCopy.Uid = dest.uidNext()
		dest.Messages = append(dest.Messages, &msgCopy)
		if uid {
			if err := dest.updateMailbox(destName, msgCopy.Uid); err != nil {
				return err
			}
		}
	}

	return nil
}

func (mbox *Mailbox) Expunge() error {
	l := log.WithFields(log.Fields{
		"package": "imap",
		"fn":      "Expunge",
	})
	l.Debug("called")
	for i := len(mbox.Messages) - 1; i >= 0; i-- {
		msg := mbox.Messages[i]
		deleted := false
		for _, flag := range msg.Flags {
			if flag == imap.DeletedFlag {
				deleted = true
				break
			}
		}
		if deleted {
			l.WithFields(log.Fields{
				"uid": msg.Uid,
			}).Debug("expunging message")
			if err := mbox.deleteMessage(msg.Uid); err != nil {
				return err
			}
			mbox.Messages = append(mbox.Messages[:i], mbox.Messages[i+1:]...)
		}
	}
	return nil
}
