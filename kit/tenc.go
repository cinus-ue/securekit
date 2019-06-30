package kit

import (
	"github.com/cinus-ue/securekit/kit/aes"
)

func AESTextEnc(plaintext, pass []byte) ([]byte, error) {
	dk, salt, err := aes.DeriveKey(pass, nil, 32)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.AESGCMEnc(plaintext, dk, salt)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func AESTextDec(ciphertext, pass []byte) ([]byte, error) {
	salt := ciphertext[len(ciphertext)-12:]
	dk, _, err := aes.DeriveKey(pass, salt, 32)
	if err != nil {
		return nil, err
	}
	plaintext, err := aes.AESGCMDec(ciphertext, dk, salt)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
