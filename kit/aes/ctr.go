package aes

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"io"
)

const (
	BufferSize int = 1024 * 1024
	HmacSize       = sha512.Size
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
	hc := hmac.New(sha512.New, key)

	writer := io.MultiWriter(dest, hc)
	writer.Write(iv)

	buf := make([]byte, BufferSize)
	for {
		n, err := src.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n != 0 {
			data := make([]byte, n)
			ctr.XORKeyStream(data, buf[:n])
			writer.Write(data)
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
	hc := hmac.New(sha512.New, key)
	hc.Write(iv)
	mac := make([]byte, HmacSize)

	buf := bufio.NewReaderSize(src, BufferSize)
	var limit int
	var data []byte
	for {
		data, err = buf.Peek(BufferSize)
		if err != nil && err != io.EOF {
			return err
		}
		limit = len(data) - HmacSize
		if err == io.EOF {
			left := buf.Buffered()
			if left < HmacSize {
				return errors.New("not enough left")
			}
			copy(mac, data[left-HmacSize:left])
			if left == HmacSize {
				break
			}
		}
		hc.Write(data[:limit])
		outBuf := make([]byte, int64(limit))
		buf.Read(data[:limit])
		ctr.XORKeyStream(outBuf, data[:limit])
		dest.Write(outBuf)
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}
	}

	if !hmac.Equal(mac, hc.Sum(nil)) {
		return ErrInvalidHMAC
	}
	return nil
}
