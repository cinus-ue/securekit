package kit

import (
	"encoding/binary"
	"io/ioutil"
	"os"
	"path"
	"strings"

	"github.com/cinus-ue/securekit/kit/aes"
	"github.com/cinus-ue/securekit/kit/rsa"
)

var (
	SKTAESVersion = []byte{0x53, 0x4B, 0x54, 0x00, 0x01}
	SKTRSAVersion = []byte{0x53, 0x4B, 0x54, 0x01, 0x01}
)

func AESFileEncrypt(source string, passphrase []byte, delete bool) error {
	if path.Ext(source) == SktExt {
		return nil
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	dk, salt, err := aes.DeriveKey(passphrase, nil, KeyLen)
	if err != nil {
		return err
	}
	var name = source + SktExt

	dest, err := os.Create(name)
	if err != nil {
		return err
	}
	dest.Write(SKTAESVersion)
	dest.Write(salt)

	err = aes.CTREncrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	src.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func AESFileDecrypt(source string, passphrase []byte, delete bool) error {
	if path.Ext(source) != SktExt {
		return nil
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	err = VersionCheck(src, SKTAESVersion)
	if err != nil {
		return err
	}
	salt := make([]byte, SaltLen)
	src.Read(salt)

	dk, _, err := aes.DeriveKey(passphrase, salt, KeyLen)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(source, SktExt)
	dest, err := os.Create(name)
	if err != nil {
		return err
	}
	err = aes.CTRDecrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	src.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func RSAFileEncrypt(source string, key string, delete bool) error {
	puk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	if path.Ext(source) == SktExt {
		return nil
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	password, err := GenerateRandomBytes(20)
	if err != nil {
		return err
	}
	dk, salt, err := aes.DeriveKey(password, nil, KeyLen)
	if err != nil {
		return err
	}

	pbytes, err := rsa.Encrypt(password, puk)
	if err != nil {
		return err
	}

	name := source + SktExt
	dest, err := os.Create(name)
	if err != nil {
		return err
	}

	psize := make([]byte, PSizeLen)
	binary.BigEndian.PutUint64(psize, uint64(len(pbytes)))

	dest.Write(SKTRSAVersion)
	dest.Write(psize)
	dest.Write(pbytes)
	dest.Write(salt)

	err = aes.CTREncrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	src.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func RSAFileDecrypt(source string, key string, delete bool) error {
	prk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	if path.Ext(source) != SktExt {
		return nil
	}
	src, err := os.Open(source)
	if err != nil {
		return err
	}

	err = VersionCheck(src, SKTRSAVersion)
	if err != nil {
		return err
	}

	psize := make([]byte, PSizeLen)
	src.Read(psize)
	pbytes := make([]byte, binary.BigEndian.Uint64(psize))
	src.Read(pbytes)
	salt := make([]byte, SaltLen)
	src.Read(salt)

	password, err := rsa.Decrypt(pbytes, prk)
	if err != nil {
		return err
	}
	dk, _, err := aes.DeriveKey(password, salt, KeyLen)
	if err != nil {
		return err
	}
	name := strings.TrimSuffix(source, SktExt)
	dest, err := os.Create(name)
	if err != nil {
		return err
	}
	err = aes.CTRDecrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(name)
		return err
	}
	src.Close()
	if delete {
		os.Remove(source)
	}
	return nil
}

func SktMsgEncrypt(plaintext, password []byte) ([]byte, error) {
	dk, salt, err := aes.DeriveKey(password, nil, KeyLen)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.GCMEncrypt(plaintext, dk, salt)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func SktMsgDecrypt(ciphertext, password []byte) ([]byte, error) {
	salt := ciphertext[len(ciphertext)-SaltLen:]
	dk, _, err := aes.DeriveKey(password, salt, KeyLen)
	if err != nil {
		return nil, err
	}
	plaintext, err := aes.GCMDecrypt(ciphertext, dk, salt)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
