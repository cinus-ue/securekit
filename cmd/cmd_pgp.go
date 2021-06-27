package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/securekit/kit/hash"
	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/kit/pgp"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/openpgp"
	"io/ioutil"
)

var Pgp = &cli.Command{
	Name:  "pgp",
	Usage: "PGP encryption and signature",
	Subcommands: []*cli.Command{
		{
			Name:   "enc",
			Usage:  "Encrypt text message",
			Action: PGPEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Decrypt text message",
			Action: PGPDecAction,
		},
		{
			Name:   "sig",
			Usage:  "Make a signature",
			Action: PGPSignAction,
		},
		{
			Name:   "vfy",
			Usage:  "Verify a signature",
			Action: PGPVerifyAction,
		},
		{
			Name:   "key",
			Usage:  "Generate new key pair",
			Action: GenerateKeyAction,
		},
		{
			Name:   "imp",
			Usage:  "Import PGP keys",
			Action: ImportKeyAction,
		},
	},
}

const (
	pgpPublicKey  = "PGP_PUBLIC_KEY"
	pgpPrivateKey = "PGP_PRIVATE_KEY"
)

func PGPEncAction(*cli.Context) error {
	entityList, err := getEntityList(pgpPublicKey)
	if err != nil {
		return err
	}
	encrypted, err := pgp.MessageEncrypt(entityList, []byte(util.GetInput("Your message:")))
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", string(encrypted))
	return nil
}

func PGPDecAction(*cli.Context) error {
	entityList, err := getEntityList(pgpPrivateKey)
	if err != nil {
		return err
	}
	encrypted := util.ReadInput("Your encrypted message:")
	entityList, err = unlock(entityList, util.ReadPassword())
	if err != nil {
		return err
	}
	decrypted, err := pgp.MessageDecrypt(entityList, encrypted)
	if err != nil {
		return err
	}
	fmt.Println("Message:", string(decrypted))
	return nil
}

func PGPSignAction(*cli.Context) error {
	filepath := util.GetInput("Please enter the path of the source file:")
	digest, err := hash.HashSum(filepath, sha256.New())
	if err != nil {
		return err
	}
	entityList, err := getEntityList(pgpPrivateKey)
	if err != nil {
		return err
	}
	entityList, err = unlock(entityList, util.ReadPassword())
	if err != nil {
		return err
	}
	signature, err := pgp.Sign(entityList[0], digest)
	if err != nil {
		return err
	}
	var sigpath = filepath + ".sig"
	path.SaveFile(sigpath, signature)
	fmt.Println("PGP Signature save to:", sigpath)
	return nil
}

func PGPVerifyAction(*cli.Context) error {
	digest, err := hash.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	entityList, err := getEntityList(pgpPublicKey)
	if err != nil {
		return err
	}
	signature, err := ioutil.ReadFile(util.GetInput("Please enter the path of the signature:"))
	if err != nil {
		return err
	}
	err = pgp.Verify(entityList[0], digest, signature)
	if err != nil {
		return err
	}
	fmt.Println("Signature verified.")
	return nil
}

func ImportKeyAction(*cli.Context) error {
	privateKey := util.ReadInput("PGP private key:")
	publicKey := util.ReadInput("PGP public key:")
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	db.Set(pgpPrivateKey, hex.EncodeToString(privateKey))
	db.Set(pgpPublicKey, hex.EncodeToString(publicKey))
	return nil
}

func GenerateKeyAction(*cli.Context) error {
	keyPair, err := pgp.GenerateKeyPair(util.GetInput("name:"),
		util.GetInput("comment:"), util.GetInput("email:"))
	if err != nil {
		return err
	}
	fmt.Println(keyPair.PublicKey)
	fmt.Println(keyPair.PrivateKey)
	return nil
}

func unlock(entityList openpgp.EntityList, passphrase []byte) (openpgp.EntityList, error) {
	for index, entity := range entityList {
		e, err := pgp.PrivateKeyDecrypt(entity, passphrase)
		if err != nil {
			return nil, err
		}
		entityList[index] = e
	}
	return entityList, nil
}

func getEntityList(key string) (openpgp.EntityList, error) {
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return nil, err
	}
	value, _ := db.Get(key)
	if len(value) == 0 {
		return nil, fmt.Errorf("%s not found in database", key)
	}
	armored, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	entityList, err := pgp.GetEntityList(armored)
	if err != nil {
		return nil, err
	}
	return entityList, nil
}
