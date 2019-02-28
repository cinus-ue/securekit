package aes

import (
	"crypto/aes"
	"crypto/cipher"
)

func AESGCMEnc(plaintext, keyAes, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyAes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	ciphertext = append(ciphertext, nonce...)
	return ciphertext, nil
}

func AESGCMDec(ciphertext, keyAes, nonce []byte) ([]byte, error) {
	block, err := aes.NewCipher(keyAes)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
