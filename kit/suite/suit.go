package suite

import (
	"errors"
	"github.com/cinus-ue/securekit/kit/suite/rsa"
	"io"

	"github.com/cinus-ue/securekit/kit/key"
	"github.com/cinus-ue/securekit/kit/suite/aes"
	"github.com/cinus-ue/securekit/kit/suite/rc4"
)

type Algorithm string

const (
	RC4       = Algorithm("RC4")
	RSA       = Algorithm("RSA")
	Aes256Gcm = Algorithm("AES-256-GCM")
	Aes256Ctr = Algorithm("AES-256-CTR")
)

var (
	algoErr = errors.New("unsupported algorithm")
)

func BlockEnc(plaintext, passphrase []byte, algorithm Algorithm) ([]byte, error) {
	switch algorithm {
	case Aes256Gcm:
		k, salt, _ := key.DeriveKey(passphrase, nil, 32)
		ciphertext, err := aes.AESGCMEncrypt(plaintext, k, salt)
		if err != nil {
			return nil, err
		}
		ciphertext = append(ciphertext, salt...)
		return ciphertext, nil
	default:
		return nil, algoErr
	}
}

func BlockDec(ciphertext, passphrase []byte, algorithm Algorithm) ([]byte, error) {
	switch algorithm {
	case Aes256Gcm:
		salt := ciphertext[len(ciphertext)-key.SaltLen:]
		k, _, _ := key.DeriveKey(passphrase, salt, 32)
		plaintext, err := aes.AESGCMDecrypt(ciphertext[:len(ciphertext)-key.SaltLen], k, salt)
		if err != nil {
			return nil, err
		}
		return plaintext, nil
	default:
		return nil, algoErr
	}
}

func StreamEnc(src io.Reader, dest io.Writer, passphrase []byte, algorithm Algorithm) (err error) {
	switch algorithm {
	case Aes256Ctr:
		k, salt, _ := key.DeriveKey(passphrase, nil, 32)
		_, err = dest.Write(salt)
		if err != nil {
			return err
		}
		return aes.AESCTREncrypt(src, dest, k)
	case RC4:
		return rc4.RC4KeyStream(src, dest, passphrase)
	default:
		return algoErr
	}
}

func StreamDec(src io.Reader, dest io.Writer, passphrase []byte, algorithm Algorithm) (err error) {
	switch algorithm {
	case Aes256Ctr:
		salt := make([]byte, key.SaltLen)
		_, err := src.Read(salt)
		if err != nil {
			return err
		}
		k, _, _ := key.DeriveKey(passphrase, salt, 32)
		return aes.AESCTRDecrypt(src, dest, k)
	case RC4:
		return rc4.RC4KeyStream(src, dest, passphrase)
	default:
		return algoErr
	}
}

func Sign(hashed, privateKey []byte, algorithm Algorithm) ([]byte, error) {
	switch algorithm {
	case RSA:
		return rsa.RSASign(hashed, privateKey)
	default:
		return nil, algoErr
	}
}

func Verify(signature, hashed, publicKey []byte, algorithm Algorithm) (bool, error) {
	switch algorithm {
	case RSA:
		return rsa.RSAVerify(signature, hashed, publicKey)
	default:
		return false, algoErr
	}
}
