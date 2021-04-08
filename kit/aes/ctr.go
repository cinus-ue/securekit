package aes

import (
	"bufio"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
)

const (
	BufferSize int = 1024 * 1024
	hash           = crypto.SHA256
	HmacSize       = sha256.Size
)

var ErrInvalidHMAC = errors.New("invalid HMAC")

func CTREncrypt(src io.Reader, dest io.Writer, key []byte) (err error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := make([]byte, cphr.BlockSize())
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(cphr, iv)
	hc := hmac.New(hash.New, key)

	writer := io.MultiWriter(dest, hc)
	writer.Write(iv)

	buf := make([]byte, BufferSize)
	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n != 0 {
			out := make([]byte, n)
			ctr.XORKeyStream(out, buf[:n])
			writer.Write(out)
		}
		if err == io.EOF {
			break
		}
	}

	dest.Write(hc.Sum(nil))
	return nil
}

func CTRDecrypt(src io.Reader, dest io.Writer, key []byte) (err error) {
	cphr, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := make([]byte, cphr.BlockSize())
	_, err = io.ReadFull(src, iv)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(cphr, iv)
	hc := hmac.New(hash.New, key)
	hc.Write(iv)
	mac := make([]byte, HmacSize)
	reader := bufio.NewReaderSize(src, BufferSize)
	var limit int
	var buf []byte
	for {
		buf, err = reader.Peek(BufferSize)
		if err != nil && err != io.EOF {
			return err
		}
		if err == io.EOF {
			left := reader.Buffered()
			if left < HmacSize {
				return errors.New("not enough left")
			}
			copy(mac, buf[left-HmacSize:left])
			if left == HmacSize {
				break
			}
		}
		limit = len(buf) - HmacSize
		hc.Write(buf[:limit])
		reader.Read(buf[:limit])
		out := make([]byte, int64(limit))
		ctr.XORKeyStream(out, buf[:limit])
		dest.Write(out)
		if err == io.EOF {
			break
		}
	}

	if !hmac.Equal(mac, hc.Sum(nil)) {
		return ErrInvalidHMAC
	}
	return nil
}
