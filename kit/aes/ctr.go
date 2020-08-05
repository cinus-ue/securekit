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
	BufferSize int = 16 * 1024
	IvSize     int = 16
	HmacSize       = sha512.Size
)

var ErrInvalidHMAC = errors.New("invalid HMAC")

func AESCTREnc(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {
	iv := make([]byte, IvSize)
	_, err = rand.Read(iv)
	if err != nil {
		return err
	}

	cphr, err := aes.NewCipher(keyAes)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(cphr, iv)
	hc := hmac.New(sha512.New, keyHmac)

	writer := io.MultiWriter(out, hc)
	writer.Write(iv)

	buf := make([]byte, BufferSize)
	for {
		n, err := in.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}

		if n != 0 {
			outBuf := make([]byte, n)
			ctr.XORKeyStream(outBuf, buf[:n])
			writer.Write(outBuf)
		}

		if err == io.EOF {
			break
		}
	}

	out.Write(hc.Sum(nil))

	return nil
}

func AESCTRDec(in io.Reader, out io.Writer, keyAes, keyHmac []byte) (err error) {
	iv := make([]byte, IvSize)
	_, err = io.ReadFull(in, iv)
	if err != nil {
		return err
	}

	cphr, err := aes.NewCipher(keyAes)
	if err != nil {
		return err
	}

	ctr := cipher.NewCTR(cphr, iv)
	hc := hmac.New(sha512.New, keyHmac)
	hc.Write(iv)
	mac := make([]byte, HmacSize)

	buf := bufio.NewReaderSize(in, BufferSize)
	var limit int
	var b []byte
	for {
		b, err = buf.Peek(BufferSize)
		if err != nil && err != io.EOF {
			return err
		}

		limit = len(b) - HmacSize

		if err == io.EOF {
			left := buf.Buffered()
			if left < HmacSize {
				return errors.New("not enough left")
			}

			copy(mac, b[left-HmacSize:left])

			if left == HmacSize {
				break
			}
		}

		hc.Write(b[:limit])

		outBuf := make([]byte, int64(limit))
		buf.Read(b[:limit])
		ctr.XORKeyStream(outBuf, b[:limit])
		out.Write(outBuf)

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
