package cmd

import (
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"strconv"

	"github.com/cinus-ue/securekit/kit"
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
			Action: EncAction,
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
			Action: DecAction,
		},
		{
			Name:   "sgt",
			Usage:  "Sign the data (file) and output the signed result",
			Action: SignAction,
		},
		{
			Name:   "vfy",
			Usage:  "Verify the signature using an RSA public key",
			Action: VerifyAction,
		},
		{
			Name:   "key",
			Usage:  "Generate RSA keys",
			Action: KeyAction,
		},
	},
}

func EncAction(c *cli.Context) error {
	var del = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")
	key := util.GetInput("Please enter the path of the public key:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}

	err = ApplyAllFiles(files, func(path string) error {
		return kit.RSAFileEncrypt(path, key, del)
	})
	return err
}

func DecAction(c *cli.Context) error {
	var del = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")
	key := util.GetInput("Please enter the path of the private key:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}

	err = ApplyAllFiles(files, func(path string) error {
		return kit.RSAFileDecrypt(path, key, del)
	})
	return err
}

func SignAction(*cli.Context) error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the private key:")

	prk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	digest, err := kit.Checksum(source, sha256.New())
	if err != nil {
		return err
	}
	signature, err := rsa.Sign(digest, prk)
	fmt.Printf("[*]Signature->%s\n", signature)
	return nil
}

func VerifyAction(*cli.Context) error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the public key:")
	signature := util.GetInput("Please enter the signature:")

	puk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	digest, err := kit.Checksum(source, sha256.New())
	if err != nil {
		return err
	}
	ret, err := rsa.Verify(signature, digest, puk)
	if err != nil {
		return err
	}
	fmt.Printf("[*]Signature valid->%t\n", ret)
	return nil
}

func KeyAction(*cli.Context) error {
	val := util.GetInput("The key size is(1024/2048/4096 bit):")
	size, err := strconv.Atoi(val)
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
	fmt.Print("Keys Generated!\n")
	return nil
}
