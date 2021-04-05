package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func GCMEncrypt(plaintext, key, salt []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, salt, plaintext, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

func GCMDecrypt(ciphertext, key, salt []byte) ([]byte, error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(cphr)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, salt, ciphertext[:len(ciphertext)-len(salt)], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
