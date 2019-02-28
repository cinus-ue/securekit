package kit

import (
	"encoding/base64"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/cinus-ue/securekit-go/kit/aes"
)

const REEXT = ".re"
const MAXLEN = 240

func Rename(source string, password []byte) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, REEXT) == 0 {
		return nil
	}
	dk, salt, err := aes.DeriveKey(password, nil, 32)
	if err != nil {
		return err
	}

	plaintext := []byte(GetFileName(source))
	ciphertext, err := aes.AESGCMEnc(plaintext, dk, salt)
	if err != nil {
		return err
	}

	basePath := GetBasePath(source)
	name := basePath + base64.URLEncoding.EncodeToString(ciphertext) + REEXT
	if len(name) > MAXLEN {
		return errors.New("the file name is too long")
	}

	err = os.Rename(source, name)
	if err != nil {
		return err
	}
	return nil
}

func Recover(source string, password []byte) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, REEXT) != 0 {
		return nil
	}
	ciphertext, err := base64.URLEncoding.DecodeString(GetFileName(source[:len(source)-len(REEXT)]))
	if err != nil {
		return err
	}
	salt := ciphertext[len(ciphertext)-12:]

	dk, _, err := aes.DeriveKey(password, salt, 32)
	if err != nil {
		return err
	}

	plaintext, err := aes.AESGCMDec(ciphertext, dk, salt)
	if err != nil {
		return err
	}

	basePath := GetBasePath(source)
	name := basePath + string(plaintext)
	err = os.Rename(source, name)
	if err != nil {
		return err
	}
	return nil
}
