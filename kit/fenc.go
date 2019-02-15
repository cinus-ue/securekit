package kit

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/cinus-ue/securekit-go/kit/rsa"
)

const AESEXT = ".aes"
const RSAEXT = ".rsa"

func AESFileEnc(source string, password []byte, delete bool, limits chan int) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, AESEXT) == 0 {
		return errors.New("the selected file has already been encrypted")
	}

	inFile, err := os.Open(source)
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

	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	if err != nil {
		return err
	}
	stream := aesctr(block, iv)

	outFile, err := os.OpenFile(source+AESEXT, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		outFile.Close()
		inFile.Close()
		if delete {
			os.Remove(source)
		}
		<-limits
	}()

	outFile.Write(iv)
	writer := &cipher.StreamWriter{S: stream, W: outFile}
	_, err = io.Copy(writer, inFile)
	if err != nil {
		return err
	}
	return nil
}

func AESFileDec(source string, password []byte, delete bool, limits chan int) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, AESEXT) != 0 {
		return errors.New("the selected file is not an encrypted file")
	}

	inFile, err := os.Open(source)
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

	iv := make([]byte, aes.BlockSize)
	inFile.Read(iv)
	stream := aesctr(block, iv)

	outFile, err := os.OpenFile(source[:len(source)-len(AESEXT)], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		outFile.Close()
		inFile.Close()
		if delete {
			os.Remove(source)
		}
		<-limits
	}()

	reader := &cipher.StreamReader{S: stream, R: inFile}
	_, err = io.Copy(outFile, reader)
	if err != nil {
		return err
	}
	return nil
}

func RSAFileEnc(source string, key string) error {
	puk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	suffix := path.Ext(source)
	if strings.Compare(suffix, RSAEXT) == 0 {
		return errors.New("the selected file has already been encrypted")
	}
	data, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}
	ciphertext, err := rsa.RSAEncrypt(data, puk)
	err = SaveFile(source+RSAEXT, ciphertext)
	if err != nil {
		return err
	}
	return nil
}

func RSAFileDec(source string, key string) error {
	prk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	suffix := path.Ext(source)
	if strings.Compare(suffix, RSAEXT) != 0 {
		return errors.New("the selected file is not an encrypted file")
	}
	data, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}
	plaintext, err := rsa.RSADecrypt(data, prk)
	err = SaveFile(source[:len(source)-len(RSAEXT)], plaintext)
	if err != nil {
		return err
	}
	return nil
}
