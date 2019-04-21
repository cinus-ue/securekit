package kit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/cinus-ue/securekit-go/kit/aes"
	"github.com/cinus-ue/securekit-go/kit/pass"
	"github.com/cinus-ue/securekit-go/kit/rsa"
)

const AES_EXT = ".aes"
const RSA_EXT = ".rsa"
const AES_VERSION = "AES-1"
const RSA_VERSION = "RSA-1"
const SALT_LEN = 12

func AESFileEnc(source string, password []byte, delete bool) error {
	suffix := path.Ext(source)
	if suffix == AES_EXT {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	dk, salt, err := aes.DeriveKey(password, nil, 32)
	if err != nil {
		return err
	}

	name := source + AES_EXT

	out, err := os.Create(name)
	if err != nil {
		return err
	}
	out.WriteString(AES_VERSION)
	out.Write(salt)

	err = aes.AESCTREnc(in, out, dk, dk)
	out.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	in.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func AESFileDec(source string, password []byte, delete bool) error {
	suffix := path.Ext(source)
	if suffix != AES_EXT {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	version := make([]byte, len([]byte(AES_VERSION)))
	in.Read(version)

	if string(version) != AES_VERSION {
		return errors.New("Inconsistent Versions:" + string(version))
	}

	salt := make([]byte, SALT_LEN)
	in.Read(salt)

	dk, _, err := aes.DeriveKey(password, salt, 32)
	if err != nil {
		return err
	}

	name := source[:len(source)-len(AES_EXT)]

	out, err := os.Create(name)
	if err != nil {
		return err
	}
	err = aes.AESCTRDec(in, out, dk, dk)
	out.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	in.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func RSAFileEnc(source string, key string, delete bool) error {
	puk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	suffix := path.Ext(source)
	if suffix == RSA_EXT {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	password, err := pass.GenerateRandomBytes(20)
	if err != nil {
		return err
	}

	dk, salt, err := aes.DeriveKey(password, nil, 32)
	if err != nil {
		return err
	}

	pass, err := rsa.RSAEncrypt(password, puk)
	if err != nil {
		return err
	}

	name := source + RSA_EXT

	out, err := os.Create(name)
	if err != nil {
		return err
	}
	out.WriteString(RSA_VERSION)
	var pSize = uint64(len(pass))
	size := make([]byte, 8)
	binary.BigEndian.PutUint64(size, uint64(pSize))
	out.Write(size)
	out.Write(pass)
	out.Write(salt)

	err = aes.AESCTREnc(in, out, dk, dk)
	out.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	in.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func RSAFileDec(source string, key string, delete bool) error {
	prk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	suffix := path.Ext(source)
	if suffix != RSA_EXT {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	version := make([]byte, len([]byte(RSA_VERSION)))
	in.Read(version)

	if string(version) != RSA_VERSION {
		return errors.New("Inconsistent Versions:" + string(version))
	}

	size := make([]byte, 8)
	in.Read(size)
	buf := bytes.NewBuffer(size)
	var pSize uint64
	binary.Read(buf, binary.BigEndian, &pSize)

	pass := make([]byte, pSize)
	in.Read(pass)
	salt := make([]byte, SALT_LEN)
	in.Read(salt)

	password, err := rsa.RSADecrypt(pass, prk)
	if err != nil {
		return err
	}
	dk, _, err := aes.DeriveKey(password, salt, 32)
	if err != nil {
		return err
	}

	name := source[:len(source)-len(RSA_EXT)]
	out, err := os.Create(name)
	if err != nil {
		return err
	}
	err = aes.AESCTRDec(in, out, dk, dk)
	out.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	in.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}
