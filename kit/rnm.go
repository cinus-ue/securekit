package kit

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/cinus-ue/securekit/kit/aes"
)

const (
	RnmVersion = "SKTRNMV1"
	MaxLen     = 240
)

func Rename(source string, passphrase []byte) error {
	fileName := GetFileName(source)
	if strings.HasPrefix(fileName, RnmVersion) {
		return nil
	}
	dk, salt, err := aes.DeriveKey(passphrase, nil, KeyLen)
	if err != nil {
		return err
	}

	ciphertext, err := aes.AESGCMEnc([]byte(fileName), dk, salt)
	if err != nil {
		return err
	}

	name := RnmVersion + base64.URLEncoding.EncodeToString(ciphertext)
	if len(name) > MaxLen {
		return errors.New("the file name is too long:" + fileName)
	}
	err = os.Rename(source, GetBasePath(source)+name)
	if err != nil {
		return err
	}
	return nil
}

func Recover(source string, passphrase []byte) error {
	fileName := GetFileName(source)
	if !strings.HasPrefix(fileName, RnmVersion) {
		return nil
	}
	ciphertext, err := base64.URLEncoding.DecodeString(fileName[len(RnmVersion):])
	if err != nil {
		return err
	}

	salt := ciphertext[len(ciphertext)-SaltLen:]
	dk, _, err := aes.DeriveKey(passphrase, salt, KeyLen)
	if err != nil {
		return err
	}

	plaintext, err := aes.AESGCMDec(ciphertext, dk, salt)
	if err != nil {
		return err
	}

	fileName = GetBasePath(source) + string(plaintext)
	err = os.Rename(source, fileName)
	if err != nil {
		return err
	}
	return nil
}
