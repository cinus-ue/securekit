package kit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"

	"github.com/cinus-ue/securekit/kit/aes"
	"github.com/cinus-ue/securekit/kit/pass"
	"github.com/cinus-ue/securekit/kit/rsa"
)

const (
	AesVersion = "SKT-AES-V1"
	RsaVersion = "SKT-RSA-V1"
)

func AESFileEnc(source string, password []byte, delete bool) error {
	suffix := path.Ext(source)
	if suffix == SktExt {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	dk, salt, err := aes.DeriveKey(password, nil, KeyLen)
	if err != nil {
		return err
	}

	name := source + SktExt

	out, err := os.Create(name)
	if err != nil {
		return err
	}
	out.WriteString(AesVersion)
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
	if suffix != SktExt {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	version := make([]byte, len([]byte(AesVersion)))
	in.Read(version)

	if string(version) != AesVersion {
		return errors.New("Inconsistent Versions:" + string(version))
	}

	salt := make([]byte, SaltLen)
	in.Read(salt)

	dk, _, err := aes.DeriveKey(password, salt, KeyLen)
	if err != nil {
		return err
	}

	name := source[:len(source)-len(SktExt)]

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
	if suffix == SktExt {
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

	dk, salt, err := aes.DeriveKey(password, nil, KeyLen)
	if err != nil {
		return err
	}

	pbytes, err := rsa.RSAEncrypt(password, puk)
	if err != nil {
		return err
	}

	name := source + SktExt

	out, err := os.Create(name)
	if err != nil {
		return err
	}
	out.WriteString(RsaVersion)
	var pSize = uint64(len(pbytes))
	size := make([]byte, PsizeLen)
	binary.BigEndian.PutUint64(size, pSize)
	out.Write(size)
	out.Write(pbytes)
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
	if suffix != SktExt {
		return nil
	}
	fmt.Printf("\n[*]processing file:%s", source)
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	version := make([]byte, len([]byte(RsaVersion)))
	in.Read(version)

	if string(version) != RsaVersion {
		return errors.New("Inconsistent Versions:" + string(version))
	}

	size := make([]byte, PsizeLen)
	in.Read(size)
	buf := bytes.NewBuffer(size)
	var pSize uint64
	binary.Read(buf, binary.BigEndian, &pSize)

	pbytes := make([]byte, pSize)
	in.Read(pbytes)
	salt := make([]byte, SaltLen)
	in.Read(salt)

	password, err := rsa.RSADecrypt(pbytes, prk)
	if err != nil {
		return err
	}
	dk, _, err := aes.DeriveKey(password, salt, KeyLen)
	if err != nil {
		return err
	}

	name := source[:len(source)-len(SktExt)]
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
