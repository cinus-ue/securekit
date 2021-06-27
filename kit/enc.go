package kit

import (
	"bytes"
	"errors"
	"os"
	"path"
	"strings"

	"github.com/cinus-ue/securekit/kit/suite"
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

func FileEncrypt(filepath, algorithm string, passphrase []byte, delete bool) error {
	if path.Ext(filepath) == sktExt {
		return nil
	}
	var src, dest, err = openEncFile(filepath)
	if err != nil {
		return err
	}
	switch algorithm {
	case SktAes:
		dest.Write(sktAesHeader)
		err = suite.StreamEncrypt(src, dest, passphrase, suite.Aes256Ctr)
	case SktRc4:
		dest.Write(sktRc4Header)
		err = suite.StreamEncrypt(src, dest, passphrase, suite.RC4)
	}
	closeFile(src, dest)
	if err != nil {
		os.Remove(dest.Name())
		return err
	}
	deleteFile(src, delete)
	return nil
}

func FileDecrypt(filepath string, passphrase []byte, delete bool) error {
	if path.Ext(filepath) != sktExt {
		return nil
	}
	var src, dest, algorithm, err = openDecFile(filepath)
	if err != nil {
		return err
	}
	switch algorithm {
	case SktAes:
		err = suite.StreamDecrypt(src, dest, passphrase, suite.Aes256Ctr)
	case SktRc4:
		err = suite.StreamDecrypt(src, dest, passphrase, suite.RC4)
	}
	closeFile(src, dest)
	if err != nil {
		os.Remove(dest.Name())
		return err
	}
	deleteFile(src, delete)
	return nil
}

func openEncFile(filepath string) (src, dest *os.File, err error) {
	src, err = os.Open(filepath)
	if err != nil {
		return
	}
	dest, err = os.Create(filepath + sktExt)
	return
}

func openDecFile(filepath string) (src, dest *os.File, algorithm string, err error) {
	src, err = os.Open(filepath)
	if err != nil {
		return
	}
	header := make([]byte, 5)
	_, _ = src.Read(header)
	if bytes.Equal(header, sktAesHeader) {
		algorithm = SktAes
	} else if bytes.Equal(header, sktRc4Header) {
		algorithm = SktRc4
	} else {
		err = errors.New("version mismatch error")
		return
	}
	dest, err = os.Create(strings.TrimSuffix(filepath, sktExt))
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
