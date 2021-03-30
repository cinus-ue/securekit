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

const (
	SaltLen  = 12
	KeyLen   = 32
	PSizeLen = 8
)

var (
	SKTAESVersion = []byte{0x53, 0x4B, 0x54, 0x00, 0x01}
	SKTRSAVersion = []byte{0x53, 0x4B, 0x54, 0x01, 0x01}
)

func AESFileEncrypt(filepath string, passphrase []byte, delete bool) error {
	if path.Ext(filepath) == SktExt {
		return nil
	}
	src, err := os.Open(filepath)
	if err != nil {
		return err
	}
	dk, salt, err := aes.DeriveKey(passphrase, nil, KeyLen)
	if err != nil {
		return err
	}
	newpath := filepath + SktExt

	dest, err := os.Create(newpath)
	if err != nil {
		return err
	}
	dest.Write(SKTAESVersion)
	dest.Write(salt)

	err = aes.CTREncrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(newpath)
		return err
	}
	src.Close()
	if delete {
		os.Remove(filepath)
	}
	return nil
}

func AESFileDecrypt(filepath string, passphrase []byte, delete bool) error {
	if path.Ext(filepath) != SktExt {
		return nil
	}
	src, err := os.Open(filepath)
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
	newpath := strings.TrimSuffix(filepath, SktExt)
	dest, err := os.Create(newpath)
	if err != nil {
		return err
	}
	err = aes.CTRDecrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(newpath)
		return err
	}
	src.Close()
	if delete {
		os.Remove(filepath)
	}
	return nil
}

func RSAFileEncrypt(filepath, keyfile string, delete bool) error {
	puk, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return err
	}
	if path.Ext(filepath) == SktExt {
		return nil
	}
	src, err := os.Open(filepath)
	if err != nil {
		return err
	}
	randpass, err := GenerateRandomBytes(20)
	if err != nil {
		return err
	}
	dk, salt, err := aes.DeriveKey(randpass, nil, KeyLen)
	if err != nil {
		return err
	}

	pbytes, err := rsa.Encrypt(randpass, puk)
	if err != nil {
		return err
	}

	newpath := filepath + SktExt
	dest, err := os.Create(newpath)
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
		os.Remove(newpath)
		return err
	}
	src.Close()
	if delete {
		os.Remove(filepath)
	}
	return nil
}

func RSAFileDecrypt(filepath, keyfile string, delete bool) error {
	prk, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return err
	}
	if path.Ext(filepath) != SktExt {
		return nil
	}
	src, err := os.Open(filepath)
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

	randpass, err := rsa.Decrypt(pbytes, prk)
	if err != nil {
		return err
	}
	dk, _, err := aes.DeriveKey(randpass, salt, KeyLen)
	if err != nil {
		return err
	}
	newpath := strings.TrimSuffix(filepath, SktExt)
	dest, err := os.Create(newpath)
	if err != nil {
		return err
	}
	err = aes.CTRDecrypt(src, dest, dk)
	dest.Close()
	if err != nil {
		os.Remove(newpath)
		return err
	}
	src.Close()
	if delete {
		os.Remove(filepath)
	}
	return nil
}

func SktMsgEncrypt(plaintext, passphrase []byte) ([]byte, error) {
	dk, salt, err := aes.DeriveKey(passphrase, nil, KeyLen)
	if err != nil {
		return nil, err
	}

	ciphertext, err := aes.GCMEncrypt(plaintext, dk, salt)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func SktMsgDecrypt(ciphertext, passphrase []byte) ([]byte, error) {
	salt := ciphertext[len(ciphertext)-SaltLen:]
	dk, _, err := aes.DeriveKey(passphrase, salt, KeyLen)
	if err != nil {
		return nil, err
	}
	plaintext, err := aes.GCMDecrypt(ciphertext, dk, salt)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}
