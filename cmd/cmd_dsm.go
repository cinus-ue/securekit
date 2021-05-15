package cmd

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/kit/security"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Dsm = &cli.Command{
	Name:  "dsm",
	Usage: "Data encryption and digital signature",
	Subcommands: []*cli.Command{
		{
			Name:   "aes-enc",
			Usage:  "Encrypt the data (file) using AES-256-CTR",
			Flags:  flags,
			Action: AESEncAction,
		},
		{
			Name:   "aes-dec",
			Usage:  "Decrypt the data (file) using AES-256-CTR",
			Flags:  flags,
			Action: AESDecAction,
		},
		{
			Name:   "rsa-enc",
			Usage:  "Encrypt the data (file) using an RSA public key",
			Flags:  flags,
			Action: RSAEncAction,
		},
		{
			Name:   "rsa-dec",
			Usage:  "Decrypt the data (file) using an RSA private key",
			Flags:  flags,
			Action: RSADecAction,
		},
		{
			Name:   "rsa-sgt",
			Usage:  "Sign the data (file) and output the signed result",
			Action: RSASignAction,
		},
		{
			Name:   "rsa-vfy",
			Usage:  "Verify the signature using an RSA public key",
			Action: RSAVerifyAction,
		},
		{
			Name:   "rsa-key",
			Usage:  "Generate RSA keys",
			Action: RSAKeyAction,
		},
	},
}

var flags = []cli.Flag{
	&cli.BoolFlag{
		Name:    "del",
		Aliases: []string{"d"},
		Usage:   "Delete source file",
	},
}

func AESEncAction(c *cli.Context) error {
	var del = c.Bool("del")
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	password := util.GetEncPassword()
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.AESFileEncrypt(path, password, del)
	})
}

func AESDecAction(c *cli.Context) error {
	var del = c.Bool("del")
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	password := util.GetDecPassword()
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.AESFileDecrypt(path, password, del)
	})
}

func RSAEncAction(c *cli.Context) error {
	var del = c.Bool("del")
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	key := util.GetInput("Please enter the path of the public key:")
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.RSAFileEncrypt(path, key, del)
	})
}

func RSADecAction(c *cli.Context) error {
	var del = c.Bool("del")
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	key := util.GetInput("Please enter the path of the private key:")
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.RSAFileDecrypt(path, key, del)
	})
}

func RSASignAction(*cli.Context) error {
	digest, err := kit.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	prk, err := ioutil.ReadFile(util.GetInput("Please enter the path of the private key:"))
	if err != nil {
		return err
	}
	signature, err := security.RSASign(digest, prk)
	fmt.Println("[*]Signature:", signature)
	return nil
}

func RSAVerifyAction(*cli.Context) error {
	digest, err := kit.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	puk, err := ioutil.ReadFile(util.GetInput("Please enter the path of the public key:"))
	if err != nil {
		return err
	}
	ret, err := security.RSAVerify(util.GetInput("Please enter the signature:"), digest, puk)
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
	privateKey, err := security.GenerateRSAKey(size)
	if err != nil {
		return err
	}
	err = security.SaveRSAKey(privateKey)
	if err != nil {
		return err
	}
	fmt.Println("Keys Generated!")
	return nil
}
