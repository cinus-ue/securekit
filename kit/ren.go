package kit

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path"
	"strings"
)

const REEXT = ".re"
const MAXLEN = 240

func Rename(source string, password []byte) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, REEXT) == 0 {
		return nil
	}
	dk, _, err := deriveKey(password, []byte(password), 32)
	if err != nil {
		return err
	}

	block, err := aescipher(dk)
	if err != nil {
		return err
	}

	plaintext := []byte(GetFileName(source))
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}

	stream := aesctr(block, iv[:])
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

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

	dk, _, err := deriveKey(password, []byte(password), 32)
	if err != nil {
		return err
	}

	block, err := aescipher(dk)
	if err != nil {
		return err
	}

	iv := ciphertext[:aes.BlockSize]
	stream := aesctr(block, iv)
	var plaintext = []byte(ciphertext[aes.BlockSize:])
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	basePath := GetBasePath(source)
	name := basePath + string(plaintext)
	err = os.Rename(source, name)
	if err != nil {
		return err
	}
	return nil
}
