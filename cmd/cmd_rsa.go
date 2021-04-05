package cmd

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/kit/rsa"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Rsa = &cli.Command{
	Name:  "rsa",
	Usage: "RSA encryption and digital signature",
	Subcommands: []*cli.Command{
		{
			Name:  "enc",
			Usage: "Encrypt the data (file) using an RSA public key",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "del",
					Aliases: []string{"d"},
					Usage:   "Delete source file",
				},
			},
			Action: RsaEncAction,
		},
		{
			Name:  "dec",
			Usage: "Decrypt the data (file) using an RSA private key",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "del",
					Aliases: []string{"d"},
					Usage:   "Delete source file",
				},
			},
			Action: RsaDecAction,
		},
		{
			Name:   "sgt",
			Usage:  "Sign the data (file) and output the signed result",
			Action: RsaSignAction,
		},
		{
			Name:   "vfy",
			Usage:  "Verify the signature using an RSA public key",
			Action: RsaVerifyAction,
		},
		{
			Name:   "key",
			Usage:  "Generate RSA keys",
			Action: RsaKeyAction,
		},
	},
}

func RsaEncAction(c *cli.Context) error {
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

func RsaDecAction(c *cli.Context) error {
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

func RsaSignAction(*cli.Context) error {
	digest, err := kit.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	prk, err := ioutil.ReadFile(util.GetInput("Please enter the path of the private key:"))
	if err != nil {
		return err
	}
	signature, err := rsa.Sign(digest, prk)
	fmt.Println("[*]Signature:", signature)
	return nil
}

func RsaVerifyAction(*cli.Context) error {
	digest, err := kit.HashSum(util.GetInput("Please enter the path of the source file:"), sha256.New())
	if err != nil {
		return err
	}
	puk, err := ioutil.ReadFile(util.GetInput("Please enter the path of the public key:"))
	if err != nil {
		return err
	}
	ret, err := rsa.Verify(util.GetInput("Please enter the signature:"), digest, puk)
	if err != nil {
		return err
	}
	fmt.Println("[*]Signature valid:", ret)
	return nil
}

func RsaKeyAction(*cli.Context) error {
	size, err := strconv.Atoi(util.GetInput("The key size is(1024/2048/4096 bit):"))
	if err != nil {
		return err
	}
	privateKey, err := rsa.GenerateRSAKey(size)
	if err != nil {
		return err
	}
	err = rsa.SaveRSAKey(privateKey)
	if err != nil {
		return err
	}
	fmt.Println("Keys Generated!")
	return nil
}
