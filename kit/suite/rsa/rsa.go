package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strconv"
)

const hash = crypto.SHA256

// RSA encrypt
func RSAEncrypt(plaintext []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	puk := pubInterface.(*rsa.PublicKey)
	segment := (puk.N.BitLen() + 7) / 8
	var start, end int
	// preventing message too long
	if segment < 2*hash.Size()+2 {
		return nil, errors.New("your key length is too short, minimum recommend:" + strconv.Itoa(2*hash.Size()+2))
	}
	var ciphertext []byte
	for i := range plaintext {
		start = i * segment / 2
		if start+segment/2 < len(plaintext) {
			end = start + segment/2
		} else {
			end = len(plaintext)
		}
		out, err := rsa.EncryptOAEP(hash.New(), rand.Reader, puk, plaintext[start:end], nil)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, out...)
		if end == len(plaintext) {
			break
		}
	}
	return ciphertext, nil
}

// RSA decrypt
func RSADecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	prk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	segment := (prk.PublicKey.N.BitLen() + 7) / 8
	var start, end int
	// preventing message too long
	if segment < 2*hash.Size()+2 {
		return nil, errors.New("your key length is too short, minimum recommend:" + strconv.Itoa(2*hash.Size()+2))
	}
	var plaintext []byte
	for i := range ciphertext {
		start = i * segment
		if start+segment < len(ciphertext) {
			end = start + segment
		} else {
			end = len(ciphertext)
		}
		out, err := rsa.DecryptOAEP(hash.New(), rand.Reader, prk, ciphertext[start:end], nil)
		if err != nil {
			return nil, err
		}
		plaintext = append(plaintext, out...)
		if end == len(ciphertext) {
			break
		}
	}
	return plaintext, nil
}

// RSA sign
func RSASign(digest, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	prk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signature, err := rsa.SignPSS(rand.Reader, prk, hash, digest, nil)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// RSA verify
func RSAVerify(signature, digest, publicKey []byte) (bool, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPSS(pubInterface.(*rsa.PublicKey), hash, digest, signature, nil)
	if err != nil {
		return false, err
	}
	return true, nil
}
