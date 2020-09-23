package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func GCMEncrypt(plaintext, key, nonce []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)
	return ciphertext, nil
}

func GCMDecrypt(ciphertext, key, nonce []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext[:len(ciphertext)-len(nonce)], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
