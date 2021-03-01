package pass

import (
	"crypto/rand"
)

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
