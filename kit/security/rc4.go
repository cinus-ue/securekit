package security

import (
	"crypto/rc4"
	"io"

	"github.com/cinus-ue/securekit/kit/base"
)

func RC4KeyStream(src io.Reader, dest io.Writer, key []byte) error {
	cipher, err := rc4.NewCipher(key)
	if err != nil {
		return err
	}
	buffer := make([]byte, base.BufferSize)
	for {
		n, err := src.Read(buffer)
		if err != nil && err != io.EOF {
			return err
		}
		outBuffer := make([]byte, n)
		cipher.XORKeyStream(outBuffer, buffer[:n])
		dest.Write(outBuffer)
		if err == io.EOF {
			break
		}
	}
	return nil
}
