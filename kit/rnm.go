package kit

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path"

	"github.com/cinus-ue/securekit/kit/aes"
)

const (
	RNM_VERSION = "SKT-RNM-V1"
	MAX_LEN     = 240
)

func Rename(source string, password []byte) error {
	suffix := path.Ext(source)
	if suffix == SKT_EXT {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)

	dk, salt, err := aes.DeriveKey(password, nil, KEY_LEN)
	if err != nil {
		return err
	}

	plaintext := []byte(GetFileName(source))
	ciphertext, err := aes.AESGCMEnc(plaintext, dk, salt)
	if err != nil {
		return err
	}

	name := GetBasePath(source) + RNM_VERSION + base64.URLEncoding.EncodeToString(ciphertext) + SKT_EXT
	if len(name) > MAX_LEN {
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
	if suffix != SKT_EXT {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)

	name := GetFileName(source[:len(source)-len(SKT_EXT)])
	version := name[:len(RNM_VERSION)]
	if string(version) != RNM_VERSION {
		return errors.New("Inconsistent Versions:" + string(version))
	}

	ciphertext, err := base64.URLEncoding.DecodeString(name[len(RNM_VERSION):])
	if err != nil {
		return err
	}

	salt := ciphertext[len(ciphertext)-SALT_LEN:]
	dk, _, err := aes.DeriveKey(password, salt, KEY_LEN)
	if err != nil {
		return err
	}

	plaintext, err := aes.AESGCMDec(ciphertext, dk, salt)
	if err != nil {
		return err
	}

	name = GetBasePath(source) + string(plaintext)
	err = os.Rename(source, name)
	if err != nil {
		return err
	}
	return nil
}
