package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/cinus-ue/securekit/kit/hash"
	"io/ioutil"
	"strconv"
	"strings"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/key"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/kit/suite"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Dsm = &cli.Command{
	Name:  "dsm",
	Usage: "Data encryption and digital signature",
	Subcommands: []*cli.Command{
		{
			Name:   "enc",
			Usage:  "Encrypt the data (file) with selected algorithm ",
			Action: FileEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Decrypt the data (file) with selected algorithm ",
			Action: FileDecAction,
		},
		{
			Name:   "sig",
			Usage:  "Sign the data (file) and output the signed result",
			Action: RSASignAction,
		},
		{
			Name:   "vfy",
			Usage:  "Verify the signature using an RSA public key",
			Action: RSAVerifyAction,
		},
		{
			Name:   "key",
			Usage:  "Generate RSA keys",
			Action: RSAKeyAction,
		},
	},
}

func FileEncAction(*cli.Context) error {
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	fmt.Print("Encryption algorithms:\n  1--AES-256-CTR\n  2--RC4\n")
	algo := util.GetInput("Select encryption algorithm [1-2]:")
	var del = false
	if strings.EqualFold(util.GetInput("delete source file(Y/N):"), "Y") {
		del = true
	}
	password := util.GetEncPassword()
	switch algo {
	case "1":
		return util.ApplyAllFiles(files, func(path string) error {
			return kit.FileEncrypt(path, kit.SktAes, password, del)
		})
	case "2":
		return util.ApplyAllFiles(files, func(path string) error {
			return kit.FileEncrypt(path, kit.SktRc4, password, del)
		})
	}
	return nil
}

func FileDecAction(*cli.Context) error {
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	var del = false
	if strings.EqualFold(util.GetInput("delete source file(Y/N):"), "Y") {
		del = true
	}
	password := util.GetDecPassword()
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.FileDecrypt(path, password, del)
	})
	return nil
}

func RSASignAction(*cli.Context) error {
	digest, err := hash.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	prk, err := ioutil.ReadFile(util.GetInput("Please enter the path of the private key:"))
	if err != nil {
		return err
	}
	signature, err := suite.Sign(digest, prk, suite.RSA)
	fmt.Println("[*]Signature:", base64.StdEncoding.EncodeToString(signature))
	return nil
}

func RSAVerifyAction(*cli.Context) error {
	digest, err := hash.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	puk, err := ioutil.ReadFile(util.GetInput("Please enter the path of the public key:"))
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(util.GetInput("Please enter the signature:"))
	if err != nil {
		return err
	}
	ret, err := suite.Verify(signature, digest, puk, suite.RSA)
	if err != nil {
		return err
	}
	fmt.Println("[*]Signature valid:", ret)
	return nil
}

func RSAKeyAction(*cli.Context) error {
	size, err := strconv.Atoi(util.GetInput("The key size is(1024/2048/4096 bit):"))
	if err != nil {
		return err
	}
	privateKey, err := key.GenerateRSAKey(size)
	if err != nil {
		return err
	}
	err = key.SaveRSAKey(privateKey)
	if err != nil {
		return err
	}
	fmt.Println("Keys Generated!")
	return nil
}
