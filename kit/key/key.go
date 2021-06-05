package key

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"os"
)

const SaltLen = 12

func DeriveKey(passphrase, salt []byte, keyLen int) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 12)
		// http://www.ietf.org/rfc/rfc2898.txt
		io.ReadFull(rand.Reader, salt)
	}
	switch keyLen {
	case 16, 24, 32: // AES 128/196/256
	default:
		return nil, nil, aes.KeySizeError(keyLen)
	}
	return pbkdf2.Key(passphrase, salt, 1000, keyLen, sha256.New), salt, nil
}

// Generate new RSA keypair
func GenerateRSAKey(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

// Stringify private key
func Stringify(privateKey *rsa.PrivateKey) (pri string, pub string, err error) {
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return
	}
	publicKeyBlock := pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	return string(pem.EncodeToMemory(&privateKeyBlock)), string(pem.EncodeToMemory(&publicKeyBlock)), nil
}

// save key
func SaveRSAKey(privateKey *rsa.PrivateKey) error {
	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	file, err := os.Create("private.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, privateKeyBlock)
	if err != nil {
		return err
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return err
	}
	publicKeyBlock := &pem.Block{
		Type:    "RSA PUBLIC KEY",
		Headers: nil,
		Bytes:   publicKeyDer,
	}
	file, err = os.Create("public.pem")
	if err != nil {
		return err
	}
	err = pem.Encode(file, publicKeyBlock)
	if err != nil {
		return err
	}
	return nil
}

// Decode Key
func DecodePrivateKey(key []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return privateKey, err
}
