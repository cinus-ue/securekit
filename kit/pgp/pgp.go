package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"

	_ "crypto/sha256"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	_ "golang.org/x/crypto/ripemd160"
)

const msgBlockType = "PGP MESSAGE"

func MessageEncrypt(entityList openpgp.EntityList, message []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	encoder, err := armor.Encode(buf, msgBlockType, make(map[string]string))
	if err != nil {
		return []byte{}, fmt.Errorf("error creating OpenPGP armor: %v", err)
	}
	encryptor, err := openpgp.Encrypt(encoder, entityList, nil, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("error creating entity for encryption: %v", err)
	}
	encryptor.Write(message)
	encryptor.Close()
	encoder.Close()
	return buf.Bytes(), nil
}

func MessageDecrypt(entityList openpgp.EntityList, encrypted []byte) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader(encrypted))
	if err != nil {
		return []byte{}, fmt.Errorf("error decoding: %v", err)
	}
	if block.Type != msgBlockType {
		return []byte{}, errors.New("invalid message type")
	}
	md, err := openpgp.ReadMessage(block.Body, entityList, nil, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading message: %v", err)
	}
	read, err := ioutil.ReadAll(md.UnverifiedBody)
	if err != nil {
		return []byte{}, fmt.Errorf("error reading unverified body: %v", err)
	}
	return read, nil
}

func StreamEncrypt(entityList openpgp.EntityList, src io.Reader, dest io.Writer) error {
	buf := new(bytes.Buffer)
	encryptor, err := openpgp.Encrypt(buf, entityList, nil, nil, nil)
	if err != nil {
		return err
	}
	_, err = io.Copy(encryptor, src)
	if err != nil {
		return err
	}
	err = encryptor.Close()
	if err != nil {
		return err
	}
	_, err = io.Copy(dest, buf)
	return err
}

func StreamDecrypt(entityList openpgp.EntityList, src io.Reader, dest io.Writer) error {
	read, err := openpgp.ReadMessage(src, entityList, nil, nil)
	if err != nil {
		return err
	}
	_, err = io.Copy(dest, read.LiteralData.Body)
	return err
}

func Sign(entity *openpgp.Entity, message []byte) ([]byte, error) {
	writer := new(bytes.Buffer)
	reader := bytes.NewReader(message)
	err := openpgp.ArmoredDetachSign(writer, entity, reader, nil)
	if err != nil {
		return []byte{}, err
	}
	return writer.Bytes(), nil
}

func Verify(entity *openpgp.Entity, message []byte, signature []byte) error {
	sig, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	hash := sig.Hash.New()
	messageReader := bytes.NewReader(message)
	_, _ = io.Copy(hash, messageReader)

	err = entity.PrimaryKey.VerifySignature(hash, sig)
	if err != nil {
		return err
	}
	return nil
}

func decodeSignature(signature []byte) (*packet.Signature, error) {
	signatureReader := bytes.NewReader(signature)
	block, err := armor.Decode(signatureReader)
	if err != nil {
		return nil, fmt.Errorf("error decoding OpenPGP Armor: %s", err)
	}

	if block.Type != openpgp.SignatureType {
		return nil, errors.New("invalid signature file")
	}

	reader := packet.NewReader(block.Body)
	pkt, err := reader.Next()
	if err != nil {
		return nil, err
	}

	sig, ok := pkt.(*packet.Signature)
	if !ok {
		return nil, errors.New("error parsing signature")
	}
	return sig, nil
}
