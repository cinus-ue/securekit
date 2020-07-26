package kit

import (
	"github.com/cinus-ue/securekit/kit/aes"
)

func AESTextEnc(plaintext, password []byte) ([]byte, error) {
	dk, salt, err := aes.DeriveKey(password, nil, KEY_LEN)
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
	salt := ciphertext[len(ciphertext)-SALT_LEN:]
	dk, _, err := aes.DeriveKey(password, salt, KEY_LEN)
	if err != nil {
		return nil, err
	}
	plaintext, err := aes.AESGCMDec(ciphertext, dk, salt)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
