package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

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

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}
