package kit

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/cinus-ue/securekit/kit/aes"
	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/kit/path"
)

const (
	RnmVersion = "SKTRNMV1"
	RnmLen     = 30
)

func Rename(source string, passphrase []byte, db *kvdb.DataBase) error {
	name := path.Name(source)
	if strings.HasPrefix(name, RnmVersion) {
		return nil
	}
	dk, salt, err := aes.DeriveKey(passphrase, nil, KeyLen)
	if err != nil {
		return err
	}
	ciphertext, err := aes.GCMEncrypt([]byte(name), dk, salt)
	if err != nil {
		return err
	}
	id := RnmVersion + GenerateRandomString(false, false, RnmLen)
	err = os.Rename(source, path.BasePath(source)+id)
	if err != nil {
		return err
	}
	return db.Set(id, base64.URLEncoding.EncodeToString(ciphertext))
}

func Recover(source string, passphrase []byte, db *kvdb.DataBase) error {
	id := path.Name(source)
	if !strings.HasPrefix(id, RnmVersion) {
		return nil
	}
	if name, ok := db.Get(id); ok {
		ciphertext, err := base64.URLEncoding.DecodeString(name)
		if err != nil {
			return err
		}
		salt := ciphertext[len(ciphertext)-SaltLen:]
		dk, _, err := aes.DeriveKey(passphrase, salt, KeyLen)
		if err != nil {
			return err
		}
		plaintext, err := aes.GCMDecrypt(ciphertext, dk, salt)
		if err != nil {
			return err
		}
		err = os.Rename(source, path.BasePath(source)+string(plaintext))
		if err != nil {
			return err
		}
		return db.Delete(id)
	}
	return errors.New("ID not found in Database")
}
