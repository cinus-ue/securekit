package pass

import (
	"math/rand"
	"time"
)

func GenerateRandomString(digit, symbol bool, length int) string {
	rand.Seed(time.Now().UnixNano())
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
		buf[i] = charset[rand.Intn(len(charset))]
	}

	return string(buf)
}
