package kit

import (
	"encoding/base64"
	"errors"
	"os"
	"strings"

	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/kit/path"
)

const (
	RnmVersion = "SKTRNMV1"
	RnmLen     = 30
)

func Rename(filepath string, passphrase []byte, db *kvdb.DataBase) error {
	name := path.Name(filepath)
	if strings.HasPrefix(name, RnmVersion) {
		return nil
	}
	ciphertext, err := SktMsgEncrypt([]byte(name), passphrase)
	if err != nil {
		return err
	}
	id := RnmVersion + GenerateRandomString(false, false, RnmLen)
	err = os.Rename(filepath, path.BasePath(filepath)+id)
	if err != nil {
		return err
	}
	return db.Set(id, base64.URLEncoding.EncodeToString(ciphertext))
}

func Recover(filepath string, passphrase []byte, db *kvdb.DataBase) error {
	id := path.Name(filepath)
	if !strings.HasPrefix(id, RnmVersion) {
		return nil
	}
	if name, ok := db.Get(id); ok {
		ciphertext, err := base64.URLEncoding.DecodeString(name)
		if err != nil {
			return err
		}
		plaintext, err := SktMsgDecrypt(ciphertext, passphrase)
		if err != nil {
			return err
		}
		err = os.Rename(filepath, path.BasePath(filepath)+string(plaintext))
		if err != nil {
			return err
		}
		return db.Delete(id)
	}
	return errors.New("ID not found in Database")
}
