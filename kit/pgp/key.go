package pgp

import (
	"bytes"
	"errors"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
)

type PGPKeyPair struct {
	PublicKey  string
	PrivateKey string
}

const (
	ArmorHeaderVersion = "SecureKit V1"
	ArmorHeaderComment = "https://github.com/cinus-ue/securekit"
)

var armorHeaders = map[string]string{
	"Version": ArmorHeaderVersion,
	"Comment": ArmorHeaderComment,
}

func GetEntityList(armored []byte) (openpgp.EntityList, error) {
	entityList, err := openpgp.ReadArmoredKeyRing(bytes.NewBuffer(armored))
	if err != nil {
		return nil, err
	}
	return entityList, nil
}

func PrivateKeyDecrypt(entity *openpgp.Entity, passphrase []byte) (*openpgp.Entity, error) {
	if entity.PrivateKey != nil && entity.PrivateKey.Encrypted {
		if len(passphrase) == 0 {
			return nil, errors.New("private key is encrypted but you did not provide a passphrase")
		}
		err := entity.PrivateKey.Decrypt(passphrase)
		if err != nil {
			return nil, errors.New("Failed to decrypt private key. Did you use the wrong passphrase? (" + err.Error() + ")")
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			err := subkey.PrivateKey.Decrypt(passphrase)
			if err != nil {
				return nil, errors.New("Failed to decrypt subkey. Did you use the wrong passphrase? (" + err.Error() + ")")
			}
		}
	}
	return entity, nil
}

func GenerateKeyPair(fullname string, comment string, email string) (PGPKeyPair, error) {
	var e *openpgp.Entity
	e, err := openpgp.NewEntity(fullname, comment, email, nil)
	if err != nil {
		return PGPKeyPair{}, err
	}

	for _, id := range e.Identities {
		err := id.SelfSignature.SignUserId(id.UserId.Id, e.PrimaryKey, e.PrivateKey, nil)
		if err != nil {
			return PGPKeyPair{}, err
		}
	}
	buf := new(bytes.Buffer)
	w, err := armor.Encode(buf, openpgp.PublicKeyType, armorHeaders)
	if err != nil {
		return PGPKeyPair{}, err
	}
	e.Serialize(w)
	w.Close()
	pubKey := buf.String()

	buf = new(bytes.Buffer)
	w, err = armor.Encode(buf, openpgp.PrivateKeyType, armorHeaders)
	if err != nil {
		return PGPKeyPair{}, err
	}
	e.SerializePrivate(w, nil)
	w.Close()
	privateKey := buf.String()

	return PGPKeyPair{
		PublicKey:  pubKey,
		PrivateKey: privateKey,
	}, nil
}

func GetPublicKeyPacket(publicKey []byte) (*packet.PublicKey, error) {
	publicKeyReader := bytes.NewReader(publicKey)
	block, err := armor.Decode(publicKeyReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PublicKeyType {
		return nil, errors.New("invalid public key data")
	}

	packetReader := packet.NewReader(block.Body)
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}

	key, ok := pkt.(*packet.PublicKey)
	if !ok {
		return nil, err
	}
	return key, nil
}

func GetPrivateKeyPacket(privateKey []byte) (*packet.PrivateKey, error) {
	privateKeyReader := bytes.NewReader(privateKey)
	block, err := armor.Decode(privateKeyReader)
	if err != nil {
		return nil, err
	}

	if block.Type != openpgp.PrivateKeyType {
		return nil, errors.New("invalid private key data")
	}

	packetReader := packet.NewReader(block.Body)
	pkt, err := packetReader.Next()
	if err != nil {
		return nil, err
	}
	key, ok := pkt.(*packet.PrivateKey)
	if !ok {
		return nil, errors.New("unable to cast to Private Key")
	}
	return key, nil
}
