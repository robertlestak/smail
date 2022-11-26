package smail

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	"github.com/robertlestak/smail/internal/persist"
	"github.com/robertlestak/smail/pkg/address"
	"github.com/robertlestak/smail/pkg/encrypt"

	log "github.com/sirupsen/logrus"
)

type Attachment struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type RawMessage struct {
	Time        time.Time    `json:"time"`
	To          []string     `json:"to"`
	CC          []string     `json:"cc"`
	BCC         []string     `json:"bcc"`
	Subject     string       `json:"subject"`
	Body        string       `json:"body"`
	Attachments []Attachment `json:"attachments"`
	FromAddr    string       `json:"from_addr"`
}

type Message struct {
	ID               string      `json:"id"`
	Raw              *RawMessage `json:"raw,omitempty"`
	ToID             string      `json:"to_id,omitempty"`
	EncryptedMessage []byte      `json:"encrypted_message,omitempty"`
}

func (m *RawMessage) ValidateInputs() error {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "NewMessage.ValidateInputs",
	})
	l.Debug("starting")
	if len(m.To) == 0 {
		return errors.New("to is required")
	}
	if m.Subject == "" {
		return errors.New("subject is required")
	}
	if m.Body == "" {
		return errors.New("body is required")
	}
	if m.FromAddr == "" {
		return errors.New("FromAddr is required")
	}
	return nil
}

func (m *RawMessage) Encrypt(pubKey []byte) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "Encrypt",
	})
	l.Debug("starting")
	jd, err := json.Marshal(m)
	if err != nil {
		l.WithError(err).Error("failed to marshal message")
		return nil, err
	}
	encStr, err := encrypt.EncryptMessage(pubKey, jd)
	if err != nil {
		l.WithError(err).Error("failed to encrypt message")
		return nil, err
	}
	if encStr == nil {
		return nil, errors.New("failed to encrypt message")
	}
	return []byte(*encStr), nil
}

func (m *Message) SpamCheck(r *http.Request) error {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "SpamCheck",
	})
	l.Debug("starting")
	// TODO: implement spam check
	return nil
}

func (m *RawMessage) CreateMessage(endpoint string, toaddr string) (*Message, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "CreateMessage",
	})
	l.Debug("starting")
	if err := m.ValidateInputs(); err != nil {
		l.WithError(err).Error("invalid inputs")
		return nil, err
	}
	toPubKey, err := GetRemotePubKey(endpoint, toaddr)
	if err != nil {
		l.WithError(err).Error("failed to get pubkey")
		return nil, err
	}
	l = l.WithField("toPubKey", toPubKey)
	l.Debug("pubkey retrieved")
	m.Time = time.Now()
	encryptedMessage, err := m.Encrypt(toPubKey)
	if err != nil {
		l.WithError(err).Error("failed to encrypt message")
		return nil, err
	}
	l = l.WithField("encryptedMessage", encryptedMessage)
	l.Debug("message encrypted")
	msg := &Message{
		Raw:              m,
		EncryptedMessage: encryptedMessage,
	}
	if err := msg.CreateID(toaddr); err != nil {
		l.WithError(err).Error("failed to create id")
		return nil, err
	}
	l = l.WithField("message", msg)
	l.Debug("message created")
	return msg, nil
}

func (m *Message) CreateID(toaddr string) error {
	h := sha512.New()
	h.Write(m.EncryptedMessage)
	m.ID = hex.EncodeToString(h.Sum(nil))
	m.ToID = address.AddressID(toaddr)
	return nil
}

func (m *Message) Send(endpoint string) error {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "Send",
	})
	l.Debug("starting")
	l = l.WithField("message", m)
	l.Debug("sending message")
	c := &http.Client{}
	m.Raw = nil
	jd, err := json.Marshal(m)
	if err != nil {
		l.WithError(err).Error("failed to marshal message")
		return err
	}
	req, err := http.NewRequest("POST", endpoint+"/message/store", bytes.NewBuffer(jd))
	if err != nil {
		l.WithError(err).Error("failed to create request")
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		l.WithError(err).Error("failed to send request")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.WithField("status", resp.StatusCode).Error("failed to send message")
		return errors.New("failed to send message")
	}
	return nil
}

func (m *Message) Store() error {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "Store",
	})
	l.Debug("starting")
	dir := path.Join(persist.DriverClient.MsgDir(), m.ToID)
	if err := persist.DriverClient.Store(dir, m.ID, m); err != nil {
		l.WithError(err).Error("failed to store message")
		return err
	}
	return nil
}

func (m *Message) Decrypt(privKeyBytes []byte) error {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "Decrypt",
	})
	l.Debug("starting")
	l = l.WithField("message", m)
	l.Debug("decrypting message")
	var pk []byte
	var err error
	if len(privKeyBytes) > 0 {
		pk = privKeyBytes
	} else {
		pk, err := address.GetPrivKey(m.ToID)
		if err != nil {
			l.WithError(err).Error("failed to get privkey")
			return nil
		}
		if pk == nil {
			return nil
		}
	}
	l = l.WithField("privKey", pk)
	l.Debug("privkey retrieved")
	dec, err := encrypt.DecryptMessage(pk, string(m.EncryptedMessage))
	if err != nil {
		l.WithError(err).Error("failed to decrypt message")
		return err
	}
	l = l.WithField("decryptedMessage", dec)
	l.Debug("message decrypted")
	m.Raw = &RawMessage{}
	if err := json.Unmarshal(dec, m.Raw); err != nil {
		l.WithError(err).Error("failed to unmarshal message")
		return err
	}
	m.EncryptedMessage = nil
	return nil
}

func EndpointFromAddr(addr string) (string, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "EndpointFromAddr",
	})
	l.Debug("starting")
	l = l.WithField("addr", addr)
	l.Debug("getting endpoint")
	if addr == "" {
		return "", errors.New("no address provided")
	}
	if !strings.Contains(addr, "@") {
		return "", errors.New("invalid address")
	}
	domain, derr := DomainFromAddr(addr)
	if derr != nil {
		l.WithError(derr).Error("invalid address")
		return "", derr
	}
	var endpoint string
	if os.Getenv("ENV") == "local" {
		endpoint = "http://localhost:8080"
	} else {
		var err error
		endpoint, err = enpointFromDomain(domain)
		if err != nil {
			l.WithError(err).Error("failed to get endpoint from domain")
			return "", err
		}
		if !strings.HasPrefix(endpoint, "http") {
			endpoint = "https://" + endpoint
		}
	}
	if os.Getenv("FORCE_SSL") == "false" {
		endpoint = strings.Replace(endpoint, "https://", "http://", 1)
	}
	l = l.WithField("endpoint", endpoint)
	l.Debug("endpoint retrieved")
	return endpoint, nil
}

type SendMessageJob struct {
	RawMessage *RawMessage
	ToAddr     string
}

func sendMessageWorker(jobs <-chan SendMessageJob, results chan<- error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "sendMessageWorker",
	})
	l.Debug("starting")
	for j := range jobs {
		l = l.WithField("job", j)
		l.Debug("processing job")
		endpoint, err := EndpointFromAddr(j.ToAddr)
		if err != nil {
			l.WithError(err).Error("failed to get endpoint from toaddr")
			results <- err
			continue
		}
		msg, err := j.RawMessage.CreateMessage(endpoint, j.ToAddr)
		if err != nil {
			l.WithError(err).Error("failed to create message")
			results <- err
			continue
		}
		l = l.WithField("message", msg)
		l.Debug("message created")
		if err := msg.Send(endpoint); err != nil {
			l.WithError(err).Error("failed to send message")
			results <- err
			continue
		}
		l.Debug("message sent")
		results <- nil
	}
}

func (m *RawMessage) Send() error {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "Send",
	})
	l.Debug("starting")
	// ensure fromaddr is valid
	// fromAddr, err := address.GetByAddr(m.FromAddr)
	// if err != nil {
	// 	l.WithError(err).Error("failed to get fromaddr")
	// 	return err
	// }
	// l = l.WithField("fromAddr", fromAddr)
	totalSend := len(m.To) + len(m.CC) + len(m.BCC)
	l = l.WithField("totalSend", totalSend)
	l.Debug("sending message")
	jobs := make(chan SendMessageJob, totalSend)
	results := make(chan error, totalSend)
	workerCount := 10
	if totalSend < workerCount {
		workerCount = totalSend
	}
	for w := 1; w <= 10; w++ {
		go sendMessageWorker(jobs, results)
	}
	tm := m
	tm.BCC = nil
	for _, to := range m.To {
		jobs <- SendMessageJob{
			RawMessage: tm,
			ToAddr:     to,
		}
	}
	for _, cc := range m.CC {
		jobs <- SendMessageJob{
			RawMessage: tm,
			ToAddr:     cc,
		}
	}
	for _, bcc := range m.BCC {
		jobs <- SendMessageJob{
			RawMessage: tm,
			ToAddr:     bcc,
		}
	}
	close(jobs)
	var errs []error
	for a := 1; a <= totalSend; a++ {
		if e := <-results; e != nil {
			l.WithError(e).Error("failed to send message")
			errs = append(errs, e)
			continue
		}
	}
	l.Debug("message sent")
	if len(errs) > 0 {
		return fmt.Errorf("failed to send message: %v", errs)
	}
	return nil
}

func DomainFromAddr(addr string) (string, error) {
	parts := strings.Split(addr, "@")
	if len(parts) != 2 {
		return "", errors.New("invalid address")
	}
	return parts[1], nil
}

func enpointFromDomain(domain string) (string, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "enpointFromDomain",
	})
	l.Debug("starting")
	// get the endpoint from the domain
	var endpoint string
	// do a DNS txt lookup for the domain
	// if the domain is not found, return an error
	// if the domain is found, return the endpoint
	txtrecords, _ := net.LookupTXT(domain)
	for _, txt := range txtrecords {
		if strings.HasPrefix(txt, "smail=") {
			endpoint = strings.TrimSpace(strings.TrimPrefix(txt, "smail="))
		}
	}
	if endpoint == "" {
		return "", errors.New("no endpoint found")
	}
	return endpoint, nil
}

func GetRemotePubKey(endpoint string, addr string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "GetRemotePubKey",
	})
	l.Debug("starting")
	a, err := address.LoadRemoteByAddress(endpoint, addr)
	if err != nil {
		l.WithError(err).Error("failed to load remote address")
		return nil, err
	}
	l = l.WithField("address", a)
	l.Debug("address loaded")
	return a.PubKey, nil
}

func LoadMessage(dir string, id string, privKeyBytes []byte) (*Message, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "LoadMessage",
		"dir": dir,
		"id":  id,
	})
	l.Debug("starting")
	m := &Message{}
	if err := persist.DriverClient.Load(dir, id, m); err != nil {
		l.WithError(err).Error("failed to load message")
		return nil, err
	}
	l = l.WithField("message", m)
	l.Debug("message loaded")
	if err := m.Decrypt(privKeyBytes); err != nil {
		l.WithError(err).Error("failed to decrypt message")
		return nil, err
	}
	return m, nil
}

func ListMessagesForAddr(id string, privKeyBytes []byte, page int, pageSize int) ([]*Message, error) {
	l := log.WithFields(log.Fields{
		"app": "smail",
		"fn":  "ListMessagesForAddr",
		"id":  id,
	})
	l.Debug("starting")
	l.Debug("getting messages")
	if id == "" {
		return nil, errors.New("invalid id")
	}
	msgs, err := persist.DriverClient.DirList(path.Join(persist.DriverClient.MsgDir(), id))
	if err != nil {
		l.WithError(err).Error("failed to get messages")
		return nil, err
	}
	// filter msgs by page and pageSize
	start := page * pageSize
	end := start + pageSize
	if start > len(msgs) {
		return nil, errors.New("invalid page")
	}
	if end > len(msgs) {
		end = len(msgs)
	}
	msgs = msgs[start:end]
	l = l.WithField("msgs", msgs)
	l.Debug("messages retrieved")
	var messages []*Message
	for _, msg := range msgs {
		l = l.WithField("msg", msg)
		l.Debug("loading message")
		dir := path.Join(persist.DriverClient.MsgDir(), id)
		m, err := LoadMessage(dir, msg, privKeyBytes)
		if err != nil {
			l.WithError(err).Error("failed to load message")
			return nil, err
		}
		messages = append(messages, m)
	}
	l = l.WithField("messages", messages)
	l.Debug("messages loaded")
	return messages, nil
}

func DeleteMessageByID(addrId string, msgId string) error {
	l := log.WithFields(log.Fields{
		"app":    "smail",
		"fn":     "DeleteMessageByID",
		"addrId": addrId,
		"msgId":  msgId,
	})
	l.Debug("starting")
	if addrId == "" {
		return errors.New("invalid addrId")
	}
	if msgId == "" {
		return errors.New("invalid msgId")
	}
	dir := path.Join(persist.DriverClient.MsgDir(), addrId)
	if err := persist.DriverClient.Delete(dir, msgId); err != nil {
		l.WithError(err).Error("failed to delete message")
		return err
	}
	return nil
}
