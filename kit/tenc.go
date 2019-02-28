package kit

import (
	"encoding/base64"
	"github.com/cinus-ue/securekit-go/kit/aes"
)

func AESTextEnc(source string, pass []byte) ([]byte, error) {
	dk, salt, err := aes.DeriveKey(pass, nil, 32)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.AESGCMEnc([]byte(source), dk, salt)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func AESTextDec(source string, pass []byte) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(source)
	if err != nil {
		return nil, err
	}
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
