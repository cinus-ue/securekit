package security

import (
	"crypto/aes"
	"crypto/cipher"
)

func AESGCMEncrypt(plaintext, key, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, salt, plaintext, nil)
	return ciphertext, nil
}

func AESGCMDecrypt(ciphertext, key, salt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, salt, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
