package pass

import (
	crypto_rand "crypto/rand"
	"encoding/base64"
	math_rand "math/rand"
	"time"
)

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := crypto_rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomPass(s int) (string, error) {
	b, err := GenerateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

func GenerateRandomString(digit, symbol bool, length int) string {
	math_rand.Seed(time.Now().UnixNano())
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	symbols := "~=+%^*/()[]{}/!@#$?|"
	if digit {
		charset = charset + digits
	}
	if symbol {
		charset = charset + symbols
	}

	buf := make([]byte, length)
	for i := 0; i < length; i++ {
		buf[i] = charset[math_rand.Intn(len(charset))]
	}

	return string(buf)
}
