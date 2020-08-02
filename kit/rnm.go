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
	RnmVersion = "SKT-RNM-V1"
	MaxLen     = 240
)

func Rename(source string, password []byte) error {
	suffix := path.Ext(source)
	if suffix == SktExt {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)

	dk, salt, err := aes.DeriveKey(password, nil, KeyLen)
	if err != nil {
		return err
	}

	plaintext := []byte(GetFileName(source))
	ciphertext, err := aes.AESGCMEnc(plaintext, dk, salt)
	if err != nil {
		return err
	}

	name := GetBasePath(source) + RnmVersion + base64.URLEncoding.EncodeToString(ciphertext) + SktExt
	if len(name) > MaxLen {
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
	if suffix != SktExt {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)

	name := GetFileName(source[:len(source)-len(SktExt)])
	version := name[:len(RnmVersion)]
	if version != RnmVersion {
		return errors.New("Inconsistent Versions:" + version)
	}

	ciphertext, err := base64.URLEncoding.DecodeString(name[len(RnmVersion):])
	if err != nil {
		return err
	}

	salt := ciphertext[len(ciphertext)-SaltLen:]
	dk, _, err := aes.DeriveKey(password, salt, KeyLen)
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
