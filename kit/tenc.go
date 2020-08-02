package kit

import (
	"github.com/cinus-ue/securekit/kit/aes"
)

func AESTextEnc(plaintext, password []byte) ([]byte, error) {
	dk, salt, err := aes.DeriveKey(password, nil, KeyLen)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.AESGCMEnc(plaintext, dk, salt)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func AESTextDec(ciphertext, password []byte) ([]byte, error) {
	salt := ciphertext[len(ciphertext)-SaltLen:]
	dk, _, err := aes.DeriveKey(password, salt, KeyLen)
	if err != nil {
		return nil, err
	}
	plaintext, err := aes.AESGCMDec(ciphertext, dk, salt)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
