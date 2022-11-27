package address

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/robertlestak/smail/internal/persist"
	"github.com/robertlestak/smail/pkg/encrypt"
	log "github.com/sirupsen/logrus"
)

var (
	PrivKeys map[string][]byte
)

type Address struct {
	ID      string `json:"id"`
	Address string `json:"address"`
	Name    string `json:"name"`
	Domain  string `json:"domain"`
	PubKey  []byte `json:"pubkey"`
	PrivKey []byte `json:"-"`
}

func (a *Address) Validate() error {
	if a.Name == "" {
		return errors.New("name is required")
	}
	if a.Domain == "" {
		return errors.New("domain is required")
	}
	if len(a.PubKey) == 0 {
		return errors.New("pubkey is required")
	}
	return nil
}

func (a *Address) CreateID() error {
	a.ID = AddressID(a.Address)
	return nil
}

func AddressID(address string) string {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "AddressID",
	})
	l.Debug("starting")
	h := sha512.New()
	h.Write([]byte(address))
	return hex.EncodeToString(h.Sum(nil))
}

func (a *Address) CreateAddress() error {
	a.Address = a.Name + "@" + a.Domain
	return nil
}

func NewAddress(name string, domain string, pubKeyBytes []byte) (*Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "NewAddress",
	})
	l.Debug("starting")
	name = strings.ToLower(name)
	domain = strings.ToLower(domain)
	a := &Address{
		Name:   name,
		Domain: domain,
		PubKey: pubKeyBytes,
	}
	if err := a.Create(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Address) Create() error {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "Create",
	})
	l.Debug("starting")
	if err := a.Validate(); err != nil {
		return err
	}
	if err := a.CreateAddress(); err != nil {
		return err
	}
	if err := a.CreateID(); err != nil {
		return err
	}
	ta := &Address{}
	if err := persist.DriverClient.Load(persist.DriverClient.AddrDir(), a.ID, ta); err == nil {
		return errors.New("address already exists")
	}
	if err := persist.DriverClient.Store(persist.DriverClient.AddrDir(), a.ID, a); err != nil {
		return err
	}
	return nil
}

func UpdateAddressPubKey(id string, pubKeyBytes []byte) error {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "UpdateAddressPubKey",
	})
	l.Debug("starting")
	a, err := LoadLocalAddressByID(id)
	if err != nil {
		return err
	}
	a.PubKey = pubKeyBytes
	if err := persist.DriverClient.Store(persist.DriverClient.AddrDir(), id, a); err != nil {
		return err
	}
	return nil
}

func LoadLocalAddressByID(id string) (*Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "LoadLocalAddressByID",
	})
	l.Debug("starting")
	a := &Address{}
	if err := persist.DriverClient.Load(persist.DriverClient.AddrDir(), id, a); err != nil {
		return nil, err
	}
	return a, nil
}

func DeleteLocalAddressByID(id string) error {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "DeleteLocalAddressByID",
	})
	l.Debug("starting")
	if err := persist.DriverClient.Delete(persist.DriverClient.AddrDir(), id); err != nil {
		return err
	}
	return nil
}

func ListLocalAddresses(page, pageSize int) ([]*Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "ListLocalAddresses",
	})
	l.Debug("starting")
	list, err := persist.DriverClient.DirList(persist.DriverClient.AddrDir())
	if err != nil {
		return nil, err
	}
	// filter list by page and pageSize
	start := page * pageSize
	end := start + pageSize
	if start > len(list) {
		return nil, errors.New("page out of range")
	}
	if end > len(list) {
		end = len(list)
	}
	list = list[start:end]
	var addrs []*Address
	for _, addr := range list {
		l.WithField("address", addr).Info("address")
		a, err := LoadLocalAddressByID(addr)
		if err != nil {
			return nil, err
		}
		addrs = append(addrs, a)
	}
	return addrs, nil
}

func GetByID(id string) (*Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "GetByID",
	})
	l.Debug("starting")
	a := &Address{}
	if err := persist.DriverClient.Load(persist.DriverClient.AddrDir(), id, a); err != nil {
		return nil, err
	}
	return a, nil
}

func GetByAddr(addr string) (*Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "GetByAddr",
	})
	l.Debug("starting")
	return GetByID(AddressID(addr))
}

func LoadRemoteByAddress(endpoint, addr string) (*Address, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "LoadRemoteByAddress",
	})
	l.Debug("starting")
	a := &Address{}
	c := &http.Client{}
	req, err := http.NewRequest("GET", endpoint+"/address/"+AddressID(addr), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("address not found")
	}
	if err := json.NewDecoder(resp.Body).Decode(a); err != nil {
		return nil, err
	}
	return a, nil
}

func GetPrivKey(id string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "GetPrivKey",
	})
	l.Debug("starting")
	if id == "" {
		l.Error("id is empty")
		return nil, errors.New("id is empty")
	}
	if pk, ok := PrivKeys[id]; ok {
		l.WithField("id", id).Debug("found private key")
		return pk, nil
	}
	a, err := LoadLocalAddressByID(id)
	if err != nil {
		l.WithError(err).Error("failed to load address")
		return nil, err
	}
	l.WithField("id", id).Debug("found local address")
	return a.PrivKey, nil
}

func LoadPrivKey(id string, privKeyBytes []byte) error {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "LoadPrivKey",
		"id":  id,
	})
	l.Debug("starting")
	if id == "" {
		return errors.New("id is empty")
	}
	// get address by id
	a, err := LoadLocalAddressByID(id)
	if err != nil {
		return err
	}
	// check if privKeyBytes is valid for pubKeyBytes
	pk, err := encrypt.BytesToPrivKey(privKeyBytes)
	if err != nil {
		return err
	}
	pubKey, err := encrypt.BytesToPubKey(a.PubKey)
	if err != nil {
		return err
	}
	if !pk.PublicKey.Equal(pubKey) {
		return errors.New("invalid private key")
	}
	// store privKeyBytes
	if PrivKeys == nil {
		PrivKeys = make(map[string][]byte)
	}
	PrivKeys[id] = privKeyBytes
	return nil
}

func GetLocalBytesUsed(id string) (int64, error) {
	l := log.WithFields(log.Fields{
		"app": "address",
		"fn":  "GetLocalBytesUsed",
	})
	l.Debug("starting")
	u, err := persist.DriverClient.MsgDirBytesUsed(id)
	if err != nil {
		return 0, err
	}
	return u, nil
}
