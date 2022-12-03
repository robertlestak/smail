package encrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"
)

type MessageHeader struct {
	Key   string `json:"k"`
	Nonce string `json:"n"`
}

func BytesToPubKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

func BytesToPrivKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	return priv, nil
}

func PrivKeyToBytes(priv *rsa.PrivateKey) []byte {
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE",
		Bytes: privBytes,
	})
}

func PubKeyBytes(pub *rsa.PublicKey) []byte {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC",
		Bytes: pubBytes,
	})
}

func RsaEncrypt(publicKey []byte, origData []byte) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "RsaEncrypt",
	})
	l.Debug("encrypting data")
	l.Debugf("public key: %s", publicKey)
	pub, err := BytesToPubKey(publicKey)
	if err != nil {
		l.Errorf("error converting public key: %v", err)
		return nil, err
	}
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, origData, nil)
}

func RsaDecrypt(privateKey []byte, ciphertext []byte) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "RsaDecrypt",
	})
	l.Debug("decrypting data")
	block, _ := pem.Decode(privateKey)
	if block == nil {
		l.Error("error decoding private key")
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ciphertext, nil)
}

func GenerateNewAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

func AESEncrypt(data, secret []byte) (string, error) {
	block, err := aes.NewCipher(secret)
	if err != nil {
		return "", err
	}
	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("could not encrypt: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)
	hd := hex.EncodeToString(ciphertext)
	return hd, nil
}

func AESDecrypt(data string, secret []byte) ([]byte, error) {
	ciphertext, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secret)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

// AesGcmEncrypt takes an encryption key and a plaintext string and encrypts it with AES256 in GCM mode, which provides authenticated encryption. Returns the ciphertext and the used nonce.
func AesGcmEncrypt(key []byte, raw []byte) ([]byte, []byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, raw, nil)
	return ciphertext, nonce, nil
}

// AesGcmDecrypt takes an decryption key, a ciphertext and the corresponding nonce and decrypts it with AES256 in GCM mode. Returns the plaintext string.
func AesGcmDecrypt(key, ciphertext, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintextBytes, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintextBytes, nil
}

func EncryptMessage(key, data []byte) (*string, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "EncryptMessage",
	})
	l.Debug("Encrypting message")
	// create a new key
	aesKey, err := GenerateNewAESKey()
	if err != nil {
		l.Error("Error generating new AES key")
		return nil, err
	}
	// encrypt the data
	ciphertext, nonce, err := AesGcmEncrypt(aesKey, data)
	if err != nil {
		l.Error("Error encrypting data")
		return nil, err
	}
	hdr := &MessageHeader{
		Key:   hex.EncodeToString(aesKey),
		Nonce: hex.EncodeToString(nonce),
	}
	hdrBytes, err := json.Marshal(hdr)
	if err != nil {
		l.Error("Error marshalling header")
		return nil, err
	}
	// encrypt the header with the rsa key
	hdrEncrypted, err := RsaEncrypt(key, hdrBytes)
	if err != nil {
		l.Error("Error encrypting header")
		return nil, err
	}
	hexHdr := hex.EncodeToString(hdrEncrypted)
	// join the header bytes and the ciphertext bytes together
	// with a string "."
	sep := "."
	mes := hexHdr + sep + hex.EncodeToString(ciphertext)
	return &mes, nil
}

func GenerateRSAKeyPair() ([]byte, []byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "GenerateRSAKeyPair",
	})
	l.Debug("Generating RSA key pair")
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		l.Error("Error generating RSA key pair")
		return nil, nil, err
	}
	publickey := &privatekey.PublicKey
	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privBytes := pem.EncodeToMemory(privateKeyBlock)
	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		l.Error("Error marshalling public key")
		return nil, nil, err
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pubBytes := pem.EncodeToMemory(publicKeyBlock)
	return privBytes, pubBytes, nil
}

func DecryptMessage(key []byte, data string) ([]byte, error) {
	l := log.WithFields(log.Fields{
		"pkg": "keys",
		"fn":  "DecryptMessage",
	})
	l.Debug("Decrypting message")
	l.Debugf("data: %s", data)
	// split the data into the header and the ciphertext
	sep := "."
	parts := strings.Split(data, sep)
	if len(parts) != 2 {
		l.Error("Error splitting data")
		return nil, errors.New("data error")
	}
	// decrypt the header
	hdrEncrypted := parts[0]
	// decode the header
	hdrBytes, err := hex.DecodeString(hdrEncrypted)
	if err != nil {
		l.Error("Error decoding header")
		return nil, err
	}
	hdrb, err := RsaDecrypt(key, hdrBytes)
	if err != nil {
		l.Error("Error decrypting header")
		return nil, err
	}
	l.Debugf("hdrb: %s", hdrb)
	// unmarshal the header
	var hdr MessageHeader
	err = json.Unmarshal(hdrb, &hdr)
	if err != nil {
		l.Error("Error unmarshalling header")
		return nil, err
	}
	// decrypt the ciphertext
	ciphertext := parts[1]
	cd, err := hex.DecodeString(ciphertext)
	if err != nil {
		l.Error("Error decoding ciphertext")
		return nil, err
	}
	l.Debugf("Key: %s", hdr.Key)
	l.Debugf("Nonce: %s", hdr.Nonce)
	kd, err := hex.DecodeString(hdr.Key)
	if err != nil {
		l.Error("Error decoding key")
		return nil, err
	}
	nd, err := hex.DecodeString(hdr.Nonce)
	if err != nil {
		l.Error("Error decoding nonce")
		return nil, err
	}
	plaintext, err := AesGcmDecrypt(kd, cd, nd)
	if err != nil {
		l.Error("Error decrypting data")
		return nil, err
	}
	return plaintext, nil
}
