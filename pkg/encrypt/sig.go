package encrypt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"
)

type SignedMessage struct {
	Message   []byte `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

type SignedRequest struct {
	Address   string        `json:"address"`
	PublicKey []byte        `json:"public_key"`
	Signature []byte        `json:"signature"`
	Hash      []byte        `json:"hash"`
	Message   SignedMessage `json:"message"`
}

func ParseSignedRequest(r *http.Request) (*SignedRequest, error) {
	l := log.WithFields(log.Fields{
		"app":  "smail",
		"func": "ParseSignedRequest",
	})
	l.Debug("starting")
	sig := r.Header.Get("X-Signature")
	if sig == "" {
		return nil, errors.New("no signature header")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return nil, err
	}
	sigReq := &SignedRequest{}
	if err := json.Unmarshal(sigBytes, &sigReq); err != nil {
		return nil, err
	}
	if len(sigReq.PublicKey) == 0 {
		return nil, errors.New("no address in signature")
	}
	pubKey, err := BytesToPubKey(sigReq.PublicKey)
	if err != nil {
		return nil, err
	}
	msgHash := sha512.New()
	jd, err := json.Marshal(sigReq.Message)
	if err != nil {
		return nil, err
	}
	_, err = msgHash.Write(jd)
	if err != nil {
		return nil, err
	}
	msgHashSum := msgHash.Sum(nil)
	err = rsa.VerifyPSS(pubKey, crypto.SHA512, msgHashSum, sigReq.Signature, nil)
	if err != nil {
		return nil, err
	}
	// check if timestamp is within 5 minutes
	if sigReq.Message.Timestamp < time.Now().Add(-5*time.Minute).Unix() {
		return nil, errors.New("signature timestamp too old")
	}
	return sigReq, nil
}

func CreateSignature(msg []byte, privateKey *rsa.PrivateKey) ([]byte, []byte, error) {
	l := log.WithFields(log.Fields{
		"app":  "smail",
		"func": "CreateSignature",
	})
	l.Debug("starting")
	msgHash := sha512.New()
	_, err := msgHash.Write(msg)
	if err != nil {
		return nil, nil, err
	}
	msgHashSum := msgHash.Sum(nil)
	sig, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, msgHashSum, nil)
	if err != nil {
		return nil, nil, err
	}
	return sig, msgHashSum, nil
}

func NewSignedRequest(key *rsa.PrivateKey) (*SignedRequest, error) {
	l := log.WithFields(log.Fields{
		"app":  "smail",
		"func": "NewSignedRequest",
	})
	l.Debug("starting")
	sr := &SignedRequest{}
	var sm SignedMessage
	sm.Timestamp = time.Now().Unix()
	jd, err := json.Marshal(sm)
	if err != nil {
		return nil, err
	}
	sr.Message = sm
	sig, hash, err := CreateSignature(jd, key)
	if err != nil {
		return nil, err
	}
	sr.Signature = sig
	sr.Hash = hash
	sr.PublicKey = PubKeyBytes(&key.PublicKey)
	return sr, nil
}

func NewSig(priv []byte) (string, error) {
	l := log.WithFields(log.Fields{
		"app":  "smail",
		"func": "NewSig",
	})
	l.Debug("starting")
	pk, err := BytesToPrivKey(priv)
	if err != nil {
		l.WithError(err).Error("error getting private key")
		return "", err
	}
	sr, err := NewSignedRequest(pk)
	if err != nil {
		l.WithError(err).Error("failed to create signed request")
		return "", err
	}
	jd, err := json.Marshal(sr)
	if err != nil {
		l.WithError(err).Error("failed to marshal signed request")
		return "", err
	}
	b64str := base64.StdEncoding.EncodeToString(jd)
	return b64str, nil
}
