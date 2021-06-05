package base

import (
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"io"
)

const BufferSize = 1024 * 1024

func GenerateRandomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func GenerateRandomString(digit, symbol bool, length int) string {
	b := GenerateRandomBytes(length)
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	symbols := "~=+%^*/()[]{}/!@#$?|"
	if digit {
		charset = charset + digits
	}
	if symbol {
		charset = charset + symbols
	}
	for i, v := range b {
		b[i] = charset[v%byte(len(charset))]
	}
	return string(b)
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

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}
