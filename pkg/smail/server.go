package smail

import (
	"encoding/json"
	"errors"
	"net/http"
	"path"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/robertlestak/smail/internal/encrypt"
	"github.com/robertlestak/smail/internal/persist"
	"github.com/robertlestak/smail/internal/utils"
	"github.com/robertlestak/smail/pkg/address"
	log "github.com/sirupsen/logrus"
)

func HandleStoreNewMessage(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "HandleStoreNewMessage",
	})
	l.Debug("starting")
	var m Message
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		l.WithError(err).Error("failed to decode body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// ensure we have a local address
	if _, err := address.GetByID(m.ToID); err != nil {
		l.WithError(err).Error("failed to get address")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := m.SpamCheck(r); err != nil {
		l.WithError(err).Error("spam check failed")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err := m.Store(); err != nil {
		l.WithError(err).Error("failed to store message")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleSendMessage(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "HandleSendMessage",
	})
	l.Debug("starting")
	sig, err := encrypt.ParseSignedRequest(r)
	if err != nil {
		l.WithError(err).Error("failed to parse signed request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var rm RawMessage
	if err := json.NewDecoder(r.Body).Decode(&rm); err != nil {
		l.WithError(err).Error("failed to decode body")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sigPubKey, err := encrypt.BytesToPubKey(sig.PublicKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	addr, err := address.GetByAddr(rm.FromAddr)
	if err != nil {
		l.WithError(err).Error("failed to get address")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aPubKey, err := encrypt.BytesToPubKey(addr.PubKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !sigPubKey.Equal(aPubKey) {
		l.Error("public key mismatch")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := rm.Send(); err != nil {
		l.WithError(err).Error("failed to send message")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	l.Debug("message sent")
}

func HandleListMessagesForAddr(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "HandleListMessagesForAddr",
	})
	l.Debug("starting")
	sig, err := encrypt.ParseSignedRequest(r)
	if err != nil {
		l.WithError(err).Error("failed to parse signed request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	vars := mux.Vars(r)
	addrID := vars["id"]
	sigPubKey, err := encrypt.BytesToPubKey(sig.PublicKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	addr, err := address.GetByID(addrID)
	if err != nil {
		l.WithError(err).Error("failed to get address")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aPubKey, err := encrypt.BytesToPubKey(addr.PubKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !sigPubKey.Equal(aPubKey) {
		l.Error("public key mismatch")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	page, pageSize := utils.PageAndPageSizeFromRequest(r)
	messages, err := ListMessagesForAddr(addrID, nil, page, pageSize)
	if err != nil {
		l.WithError(err).Error("failed to list messages")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(messages); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleDeleteMessageById(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "HandleDeleteMessageById",
	})
	l.Debug("starting")
	vars := mux.Vars(r)
	addrId := vars["addr_id"]
	msgID := vars["id"]
	sig, err := encrypt.ParseSignedRequest(r)
	if err != nil {
		l.WithError(err).Error("failed to parse signed request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sigPubKey, err := encrypt.BytesToPubKey(sig.PublicKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	addr, err := address.GetByID(addrId)
	if err != nil {
		l.WithError(err).Error("failed to get address")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aPubKey, err := encrypt.BytesToPubKey(addr.PubKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !sigPubKey.Equal(aPubKey) {
		l.Error("public key mismatch")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := DeleteMessageByID(addrId, msgID); err != nil {
		l.WithError(err).Error("failed to delete message")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleGetMessageById(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "HandleGetMessageById",
	})
	l.Debug("starting")
	vars := mux.Vars(r)
	addrId := vars["addr_id"]
	msgID := vars["id"]
	sig, err := encrypt.ParseSignedRequest(r)
	if err != nil {
		l.WithError(err).Error("failed to parse signed request")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	sigPubKey, err := encrypt.BytesToPubKey(sig.PublicKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	addr, err := address.GetByID(addrId)
	if err != nil {
		l.WithError(err).Error("failed to get address")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	aPubKey, err := encrypt.BytesToPubKey(addr.PubKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if !sigPubKey.Equal(aPubKey) {
		l.Error("public key mismatch")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	m, err := LoadMessage(path.Join(persist.DriverClient.MsgDir(), addrId), msgID, nil)
	if err != nil {
		l.WithError(err).Error("failed to get message")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func GetMessages(server string, addrId string, sig string, page int, pageSize int) ([]*Message, error) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "GetMessages",
	})
	l.Debug("starting")
	req, err := http.NewRequest("GET", server+"/messages/"+addrId, nil)
	if err != nil {
		l.WithError(err).Error("failed to create request")
		return nil, err
	}
	q := req.URL.Query()
	if page > 0 {
		q.Add("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Add("page_size", strconv.Itoa(pageSize))
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.WithError(err).Error("failed to make request")
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.WithField("status", resp.StatusCode).Error("bad status")
		return nil, errors.New("bad status")
	}
	var messages []*Message
	if err := json.NewDecoder(resp.Body).Decode(&messages); err != nil {
		l.WithError(err).Error("failed to decode json")
		return nil, err
	}
	return messages, nil
}

func DeleteMessage(server string, addrId string, msgId string, sig string) error {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "DeleteMessage",
	})
	l.Debug("starting")
	req, err := http.NewRequest("DELETE", server+"/messages/"+addrId+"/"+msgId, nil)
	if err != nil {
		l.WithError(err).Error("failed to create request")
		return err
	}
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.WithError(err).Error("failed to make request")
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.WithField("status", resp.StatusCode).Error("bad status")
		return errors.New("bad status")
	}
	return nil
}

func GetMessage(server string, addrId string, msgId string, sig string) (*Message, error) {
	l := log.WithFields(log.Fields{
		"app": "server",
		"fn":  "GetMessage",
	})
	l.Debug("starting")
	req, err := http.NewRequest("GET", server+"/messages/"+addrId+"/"+msgId, nil)
	if err != nil {
		l.WithError(err).Error("failed to create request")
		return nil, err
	}
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		l.WithError(err).Error("failed to make request")
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		l.WithField("status", resp.StatusCode).Error("bad status")
		return nil, errors.New("bad status")
	}
	var message *Message
	if err := json.NewDecoder(resp.Body).Decode(&message); err != nil {
		l.WithError(err).Error("failed to decode json")
		return nil, err
	}
	return message, nil
}
