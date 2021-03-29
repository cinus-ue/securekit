package kit

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"io"
)

const (
	SktExt   = ".skt"
	SaltLen  = 12
	KeyLen   = 32
	PSizeLen = 8
)

func VersionCheck(src io.Reader, versionRequirement []byte) error {
	version := make([]byte, len(versionRequirement))
	_, _ = src.Read(version)
	if !bytes.Equal(version, versionRequirement) {
		return errors.New("Inconsistent Version:" + string(version))
	}
	return nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomString(digit, symbol bool, length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	symbols := "~=+%^*/()[]{}/!@#$?|"
	if digit {
		charset = charset + digits
	}
	if symbol {
		charset = charset + symbols
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes)
}

func Compress(input []byte) []byte {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	writer.Write(input)
	writer.Close()
	output := buf.Bytes()
	return output
}

func Decompress(input []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	b := bytes.NewReader(input)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	io.Copy(w, r)
	r.Close()
	output := buf.Bytes()
	return output, nil
}
