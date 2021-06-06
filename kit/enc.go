package kit

import (
	"bytes"
	"errors"
	"github.com/cinus-ue/securekit/kit/suite"
	"io"
	"os"
	"path"
	"strings"
)

const (
	SktAes = "SKT-AES"
	SktRc4 = "SKT-RC4"
	sktExt = ".skt"
)

var (
	sktAesHeader = []byte{0x53, 0x4B, 0x54, 0x00, 0x02}
	sktRc4Header = []byte{0x53, 0x4B, 0x54, 0x02, 0x02}
)

func fileHeader(src io.Reader) (string, error) {
	head := make([]byte, 5)
	_, _ = src.Read(head)
	if bytes.Equal(head, sktAesHeader) {
		return SktAes, nil
	} else if bytes.Equal(head, sktRc4Header) {
		return SktRc4, nil
	}
	return "", errors.New("version mismatch error")
}

func beforeEncrypt(filepath string) (src, dest *os.File, err error) {
	src, err = os.Open(filepath)
	if err != nil {
		return
	}
	dest, err = os.Create(filepath + sktExt)
	return
}

func closeFile(src, dest *os.File) {
	src.Close()
	dest.Close()
}

func deleteFile(file *os.File, delete bool) {
	if delete {
		os.Remove(file.Name())
	}
}

func FileEncrypt(filepath, algorithm string, passphrase []byte, delete bool) error {
	if path.Ext(filepath) == sktExt {
		return nil
	}
	src, dest, err := beforeEncrypt(filepath)
	if err != nil {
		return err
	}
	switch algorithm {
	case SktAes:
		dest.Write(sktAesHeader)
		err = suite.StreamEnc(src, dest, passphrase, suite.Aes256Ctr)
	case SktRc4:
		dest.Write(sktRc4Header)
		err = suite.StreamEnc(src, dest, passphrase, suite.RC4)
	}
	closeFile(src, dest)
	if err != nil {
		os.Remove(dest.Name())
		return err
	}
	deleteFile(src, delete)
	return nil
}

func FileDecrypt(filepath string, key []byte, delete bool) error {
	if path.Ext(filepath) != sktExt {
		return nil
	}
	src, err := os.Open(filepath)
	if err != nil {
		return err
	}
	header, err := fileHeader(src)
	if err != nil {
		return err
	}
	dest, err := os.Create(strings.TrimSuffix(filepath, sktExt))
	if err != nil {
		return err
	}
	switch header {
	case SktAes:
		err = suite.StreamDec(src, dest, key, suite.Aes256Ctr)
	case SktRc4:
		err = suite.StreamDec(src, dest, key, suite.RC4)
	}
	closeFile(src, dest)
	if err != nil {
		os.Remove(dest.Name())
		return err
	}
	deleteFile(src, delete)
	return nil
}
