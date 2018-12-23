package kit

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"golang.org/x/crypto/pbkdf2"
	"io"
)

func DeriveKey(passphrase, salt []byte, keyLen int) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 12)
		// http://www.ietf.org/rfc/rfc2898.txt
		io.ReadFull(rand.Reader, salt)
	}
	switch keyLen {
	case 16, 24, 32: // AES 128/196/256
	default:
		return nil, nil, aes.KeySizeError(keyLen)
	}
	return pbkdf2.Key(passphrase, salt, 1000, keyLen, sha256.New), salt, nil
}

func AESCipher(dk []byte) (cipher.Block, error) {
	blk, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	return blk, nil
}

func AESGCM(block cipher.Block) (cipher.AEAD, error) {
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead, nil
}

func AESCTR(block cipher.Block, iv []byte) cipher.Stream {
	stream := cipher.NewCTR(block, iv)
	return stream
}

func AESCBC(block cipher.Block, iv []byte, enc bool) cipher.BlockMode {
	if enc {
		blockmode := cipher.NewCBCEncrypter(block, iv)
		return blockmode
	}
	blockmode := cipher.NewCBCDecrypter(block, iv)
	return blockmode
}

func AESCFB(block cipher.Block, iv []byte, enc bool) cipher.Stream {
	if enc {
		stream := cipher.NewCFBEncrypter(block, iv)
		return stream
	}
	stream := cipher.NewCFBDecrypter(block, iv)
	return stream
}

func AESOFB(block cipher.Block, iv []byte) cipher.Stream {
	stream := cipher.NewOFB(block, iv)
	return stream
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(plaintext []byte) []byte {
	length := len(plaintext)
	unpadding := int(plaintext[length-1])
	return plaintext[:(length - unpadding)]
}
