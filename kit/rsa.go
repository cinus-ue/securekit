package kit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strconv"
)

// RSA encrypt
func RSAEncrypt(plaintext []byte, publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	CheckErr(err)
	puk := pubInterface.(*rsa.PublicKey)
	segment := (puk.N.BitLen() + 7) / 8
	hash := crypto.SHA256
	var start, end int
	// preventing message too long
	if segment < 2*hash.Size()+2 {
		return nil, errors.New("your key length is too short, minimum recommend:" + strconv.Itoa(2*hash.Size()+2))
	}
	var data []byte
	for i := range plaintext {
		start = i * segment / 2
		if start+segment/2 < len(plaintext) {
			end = start + segment/2
		} else {
			end = len(plaintext)
		}
		byteSequence := plaintext[start:end]
		segmentEncrypt, err := rsa.EncryptOAEP(hash.New(), rand.Reader, puk, byteSequence, nil)
		CheckErr(err)
		data = append(data, segmentEncrypt...)
		if end == len(plaintext) {
			break
		}
	}
	return data, nil
}

// RSA decrypt
func RSADecrypt(ciphertext []byte, privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	prk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	CheckErr(err)
	segment := (prk.PublicKey.N.BitLen() + 7) / 8
	hash := crypto.SHA256
	var start, end int
	// preventing message too long
	if segment < 2*hash.Size()+2 {
		return nil, errors.New("your key length is too short, minimum recommend:" + strconv.Itoa(2*hash.Size()+2))
	}
	var data []byte
	for i := range ciphertext {
		start = i * segment
		if start+segment < len(ciphertext) {
			end = start + segment
		} else {
			end = len(ciphertext)
		}
		segmentEncrypt := ciphertext[start:end]
		segmentDecrypt, err := rsa.DecryptOAEP(hash.New(), rand.Reader, prk, segmentEncrypt, nil)
		CheckErr(err)
		data = append(data, segmentDecrypt...)
		if end == len(ciphertext) {
			break
		}
	}
	return data, nil
}

// RSA sign
func RSASign(origdata, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	prk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	CheckErr(err)
	digest := SHA256(origdata)
	body, err := rsa.SignPKCS1v15(rand.Reader, prk, crypto.SHA256, digest)
	CheckErr(err)
	return base64.StdEncoding.EncodeToString(body), nil
}

// RSA verify
func RSAVerify(signature string, originData,publicKey []byte) (bool, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	CheckErr(err)
	puk := pubInterface.(*rsa.PublicKey)
	digest := SHA256(originData)
	body, err := base64.StdEncoding.DecodeString(signature)
	CheckErr(err)
	err = rsa.VerifyPKCS1v15(puk, crypto.SHA256, digest, body)
	CheckErr(err)
	return true, nil
}
