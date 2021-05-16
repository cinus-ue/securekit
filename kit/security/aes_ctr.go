package security

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"io"
)

const (
	bufferSize int = 1024 * 1024
	hmacHash       = crypto.SHA256
)

func AESCTREncrypt(src io.Reader, dest io.Writer, key []byte) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := make([]byte, block.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(block, iv)
	hc := hmac.New(hmacHash.New, key)
	writer := io.MultiWriter(dest, hc)
	_, _ = writer.Write(iv)
	buffer := make([]byte, bufferSize)
	for {
		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n != 0 {
			outBuffer := make([]byte, n)
			ctr.XORKeyStream(outBuffer, buffer[:n])
			_, _ = writer.Write(outBuffer)
			_, _ = writer.Write(hc.Sum(nil))
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}

func AESCTRDecrypt(src io.Reader, dest io.Writer, key []byte) (err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := make([]byte, block.BlockSize())
	_, err = io.ReadFull(src, iv)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(block, iv)
	hc := hmac.New(hmacHash.New, key)
	hc.Write(iv)
	var hmacSize = hmacHash.Size()
	buffer := make([]byte, bufferSize+hmacSize)
	for {
		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		if n != 0 {
			limit := n - hmacSize
			hc.Write(buffer[:limit])
			tag := hc.Sum(nil)
			if !hmac.Equal(buffer[limit:n], tag) {
				return errors.New("invalid HMAC")
			}
			hc.Write(tag)
			outBuffer := make([]byte, limit)
			ctr.XORKeyStream(outBuffer, buffer[:limit])
			_, _ = dest.Write(outBuffer)
		}
		if err == io.EOF {
			break
		}
	}
	return nil
}
