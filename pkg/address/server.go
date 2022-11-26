package address

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/robertlestak/smail/internal/encrypt"
	"github.com/robertlestak/smail/internal/utils"
	log "github.com/sirupsen/logrus"
)

func validateServerKey(r *http.Request) error {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "validateServerKey",
	})
	l.Debug("starting")
	sig, err := encrypt.ParseSignedRequest(r)
	if err != nil {
		l.WithError(err).Error("failed to parse signed request")
		return err
	}
	sigPubKey, err := encrypt.BytesToPubKey(sig.PublicKey)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		return err
	}
	bd, err := base64.StdEncoding.DecodeString(os.Getenv("SERVER_PUBLIC_KEY_BASE64"))
	if err != nil {
		l.WithError(err).Error("failed to decode server public key")
		return err
	}
	serverPubKey, err := encrypt.BytesToPubKey(bd)
	if err != nil {
		l.WithError(err).Error("failed to convert bytes to public key")
		return err
	}
	if !sigPubKey.Equal(serverPubKey) {
		l.Error("public key mismatch")
		return errors.New("public key mismatch")
	}
	return nil
}

func HandleListLocalAddresses(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleListLocalAddresses",
	})
	l.Debug("starting")
	if err := validateServerKey(r); err != nil {
		l.Error("failed to validate server key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	page, pageSize := utils.PageAndPageSizeFromRequest(r)
	addrs, err := ListLocalAddresses(page, pageSize)
	if err != nil {
		l.WithError(err).Error("failed to list local addresses")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(addrs); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleCreateNewAddress(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleCreateNewAddress",
	})
	l.Debug("starting")
	if err := validateServerKey(r); err != nil {
		l.Error("failed to validate server key")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var a *Address
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		l.WithError(err).Error("failed to decode json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := a.Create(); err != nil {
		l.WithError(err).Error("failed to create address")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(a); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleDeleteAddressByID(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleDeleteAddressByID",
	})
	l.Debug("starting")
	vars := mux.Vars(r)
	id := vars["id"]
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
	addr, err := GetByID(id)
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
	if err := DeleteLocalAddressByID(id); err != nil {
		l.WithError(err).Error("failed to delete address")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func HandleUpdateAddressPubKey(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleUpdateAddressPubKey",
	})
	l.Debug("starting")
	vars := mux.Vars(r)
	id := vars["id"]
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
	addr, err := GetByID(id)
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
	var a *Address
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		l.WithError(err).Error("failed to decode json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if err := UpdateAddressPubKey(id, a.PubKey); err != nil {
		l.WithError(err).Error("failed to update address")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(a); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleGetByID(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleGetByID",
	})
	l.Debug("starting")
	vars := mux.Vars(r)
	id := vars["id"]
	a, err := GetByID(id)
	a.PrivKey = nil
	if err != nil {
		l.WithError(err).Error("failed to get address")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(a); err != nil {
		l.WithError(err).Error("failed to encode json")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleLoadPrivKey(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleLoadPrivKey",
	})
	l.Debug("starting")
	var a *Address
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		l.WithError(err).Error("failed to decode json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		l.Error("id is required")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
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
	addr, err := GetByID(id)
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
	if err := LoadPrivKey(id, a.PrivKey); err != nil {
		l.WithError(err).Error("failed to load private key")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func HandleDeletePrivKeyByID(w http.ResponseWriter, r *http.Request) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "HandleDeletePrivKeyByID",
	})
	l.Debug("starting")
	vars := mux.Vars(r)
	id := vars["id"]
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
	addr, err := GetByID(id)
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
	delete(PrivKeys, id)
	w.WriteHeader(http.StatusNoContent)
}

func ListAddresses(server string, sig string, page int, pageSize int) ([]Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "ListAddresses",
	})
	l.Debug("starting")
	var addresses []Address
	req, err := http.NewRequest("GET", server+"/addresses", nil)
	if err != nil {
		return addresses, err
	}
	q := req.URL.Query()
	if page > 0 {
		q.Add("page", strconv.Itoa(page))
	}
	if pageSize > 0 {
		q.Add("page_size", strconv.Itoa(pageSize))
	}
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return addresses, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&addresses); err != nil {
		return addresses, err
	}
	return addresses, nil
}

func DeleteAddress(server string, id string, sig string) error {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "DeleteAddress",
	})
	l.Debug("starting")
	req, err := http.NewRequest("DELETE", server+"/address/"+id, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func CreateAddress(server string, sig string, name string, domain string, pubKeyBytes []byte) (Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "CreateAddress",
	})
	l.Debug("starting")
	addr := Address{
		Name:   name,
		Domain: domain,
		PubKey: pubKeyBytes,
	}
	b, err := json.Marshal(addr)
	if err != nil {
		return addr, err
	}
	req, err := http.NewRequest("POST", server+"/address", bytes.NewBuffer(b))
	if err != nil {
		return addr, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return addr, err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&addr); err != nil {
		return addr, err
	}
	return addr, nil
}
