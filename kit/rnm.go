package kit

import (
	"encoding/base64"
	"errors"
	"github.com/cinus-ue/securekit/kit/suite"
	"os"
	"strings"

	"github.com/cinus-ue/securekit/kit/base"
	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/kit/path"
)

const (
	rnmVersion = "SKTRNMV1"
	rnmLen     = 30
	algo       = suite.Aes256Gcm
)

func Rename(filepath string, passphrase []byte, db *kvdb.DataBase) error {
	name := path.Name(filepath)
	if strings.HasPrefix(name, rnmVersion) {
		return nil
	}
	ciphertext, err := suite.BlockEnc([]byte(name), passphrase, algo)
	if err != nil {
		return err
	}
	key := rnmVersion + base.GenerateRandomString(false, false, rnmLen)
	err = os.Rename(filepath, path.BasePath(filepath)+key)
	if err != nil {
		return err
	}
	return db.Set(key, base64.URLEncoding.EncodeToString(ciphertext))
}

func Recover(filepath string, passphrase []byte, db *kvdb.DataBase) error {
	key := path.Name(filepath)
	if !strings.HasPrefix(key, rnmVersion) {
		return nil
	}
	if name, ok := db.Get(key); ok {
		ciphertext, err := base64.URLEncoding.DecodeString(name)
		if err != nil {
			return err
		}
		plaintext, err := suite.BlockDec(ciphertext, passphrase, algo)
		if err != nil {
			return err
		}
		err = os.Rename(filepath, path.BasePath(filepath)+string(plaintext))
		if err != nil {
			return err
		}
		return db.Delete(key)
	}
	return errors.New("ID not found in Database")
}
