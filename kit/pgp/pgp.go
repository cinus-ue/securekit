package pgp

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp"
)

// gpg --output {out} --encrypt {file} -r {recipient/public key}
func PGPFileEnc(key []byte, src io.Reader, dest io.Writer) error {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(key))
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	encrypter, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return err
	}

	_, err = io.Copy(encrypter, src)
	if err != nil {
		return err
	}

	err = encrypter.Close()
	if err != nil {
		return err
	}

	_, err = io.Copy(dest, buf)
	return err
}

// gpg --output {out} --passphrase {passphrase} --decrypt {file}
func PGPFileDec(key, passphrase []byte, src io.Reader, dest io.Writer) error {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(key))
	if err != nil {
		return err
	}
	entity := entityList[0]

	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if len(passphrase) == 0 {
			return errors.New("Private key is encrypted but you did not provide a passphrase")
		}
		err := entity.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return errors.New("Failed to decrypt private key. Did you use the wrong passphrase? (" + err.Error() + ")")
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt(passphrase)
			if err != nil {
				return errors.New("Failed to decrypt subkey. Did you use the wrong passphrase? (" + err.Error() + ")")
			}
		}
	}

	read, err := openpgp.ReadMessage(src, entityList, nil, nil)
	if err != nil {
		return err
	}

	_, err = io.Copy(dest, read.LiteralData.Body)
	return err

}
