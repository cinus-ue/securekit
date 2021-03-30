package kit

import (
	"bufio"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"hash"
	"io"
	"os"
)

// MD5-32
func Md532(data []byte) []byte {
	h := md5.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHA-1
func SHA1(data []byte) []byte {
	h := sha1.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHA-256
func SHA256(data []byte) []byte {
	h := sha256.New()
	h.Write(data)
	return h.Sum(nil)
}

// SHA-384
func SHA384(data []byte) []byte {
	h := sha512.New384()
	h.Write(data)
	return h.Sum(nil)
}

// SHA-512
func SHA512(data []byte) []byte {
	h := sha512.New()
	h.Write(data)
	return h.Sum(nil)
}

// HmacSha256
func HmacSha256(publicKey, privateKey []byte) []byte {
	mac := hmac.New(sha256.New, privateKey)
	mac.Write(publicKey)
	return mac.Sum(nil)
}

// HmacSha1
func HmacSha1(publicKey, privateKey []byte) []byte {
	mac := hmac.New(sha1.New, privateKey)
	mac.Write(publicKey)
	return mac.Sum(nil)
}

// Pbkdf2Sha256
func Pbkdf2Sha256(data, salt string, iterations int) string {
	dk := pbkdf2.Key([]byte(data), []byte(salt), iterations, 32, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", iterations, salt, base64.StdEncoding.EncodeToString(dk))
}

func Checksum(path string, hash hash.Hash) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	_, err = io.Copy(hash, reader)
	if err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}
