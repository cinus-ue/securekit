package kit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/cinus-ue/securekit-go/kit/pass"
	"github.com/cinus-ue/securekit-go/kit/rsa"
)

const AESEXT = ".aes"
const RSAEXT = ".rsa"
const AES_VERSION = "AES-1"
const RSA_VERSION = "RSA-1"
const SALT_LEN =12


func AESFileEnc(source string, password []byte, delete bool, limits chan int) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, AESEXT) == 0 {
		return errors.New("the selected file has already been encrypted")
	}

	in, err := os.Open(source)
	if err != nil {
		return err
	}

	dk, salt, err := deriveKey(password, nil, 32)
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

	out, err := os.OpenFile(source+AESEXT, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		out.Close()
		in.Close()
		if delete {
			os.Remove(source)
		}
		<-limits
	}()

	out.WriteString(AES_VERSION)
	out.Write(iv)
	out.Write(salt)
	writer := &cipher.StreamWriter{S: stream, W: out}
	_, err = io.Copy(writer, in)
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

	in, err := os.Open(source)
	if err != nil {
		return err
	}


	version := make([]byte,len([]byte(AES_VERSION)))
	in.Read(version)

	if strings.Compare(string(version), AES_VERSION) != 0 {
		return errors.New("Inconsistent Versions:"+string(version))
	}

	iv := make([]byte, aes.BlockSize)
	in.Read(iv)
	salt := make([]byte,SALT_LEN)
	in.Read(salt)

	dk, _, err := deriveKey(password, salt, 32)
	if err != nil {
		return err
	}

	block, err := aescipher(dk)
	if err != nil {
		return err
	}
	stream := aesctr(block, iv)

	out, err := os.OpenFile(source[:len(source)-len(AESEXT)], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		out.Close()
		in.Close()
		if delete {
			os.Remove(source)
		}
		<-limits
	}()

	reader := &cipher.StreamReader{S: stream, R: in}
	_, err = io.Copy(out, reader)
	if err != nil {
		return err
	}
	return nil
}

func RSAFileEnc(source string, key string, delete bool, limits chan int) error {
	puk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	suffix := path.Ext(source)
	if strings.Compare(suffix, RSAEXT) == 0 {
		return errors.New("the selected file has already been encrypted")
	}

	password, err := pass.GenerateRandomBytes(20)
	if err != nil {
		return err
	}

	in, err := os.Open(source)
	if err != nil {
		return err
	}

	dk, salt, err := deriveKey(password, nil, 32)
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

	out, err := os.OpenFile(source+RSAEXT, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		out.Close()
		in.Close()
		if delete {
			os.Remove(source)
		}
		<-limits
	}()

	pass, err := rsa.RSAEncrypt(password, puk)
	if err != nil {
		return err
	}
	out.WriteString(RSA_VERSION)
	var pSize = uint64(len(pass))
	size := make([]byte, 8)
	binary.BigEndian.PutUint64(size, uint64(pSize))
	out.Write(size)
	out.Write(pass)
	out.Write(iv)
	out.Write(salt)

	writer := &cipher.StreamWriter{S: stream, W: out}
	_, err = io.Copy(writer, in)
	if err != nil {
		return err
	}
	return nil
}

func RSAFileDec(source string, key string, delete bool, limits chan int) error {
	prk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	suffix := path.Ext(source)
	if strings.Compare(suffix, RSAEXT) != 0 {
		return errors.New("the selected file is not an encrypted file")
	}

	in, err := os.Open(source)
	if err != nil {
		return err
	}

	version := make([]byte,len([]byte(RSA_VERSION)))
	in.Read(version)

	if strings.Compare(string(version), RSA_VERSION) != 0 {
		return errors.New("Inconsistent Versions:"+string(version))
	}

	size := make([]byte,8)
	in.Read(size)
	buf := bytes.NewBuffer(size)
	var pSize uint64
	binary.Read(buf, binary.BigEndian, &pSize)

	pass := make([]byte,pSize)
	in.Read(pass)
	iv := make([]byte, aes.BlockSize)
	in.Read(iv)
	salt := make([]byte,SALT_LEN)
	in.Read(salt)

	password, err := rsa.RSADecrypt(pass, prk)
	if err != nil {
		return err
	}
	dk, _, err := deriveKey(password, salt, 32)
	if err != nil {
		return err
	}

	block, err := aescipher(dk)
	if err != nil {
		return err
	}

	stream := aesctr(block, iv)
	out, err := os.OpenFile(source[:len(source)-len(RSAEXT)], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	defer func() {
		out.Close()
		in.Close()
		if delete {
			os.Remove(source)
		}
		<-limits
	}()

	reader := &cipher.StreamReader{S: stream, R: in}
	_, err = io.Copy(out, reader)
	if err != nil {
		return err
	}
	return nil
}
