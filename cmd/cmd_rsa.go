package cmd

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

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
	for files.Len() > 0 {
		limits <- 1
		path := files.Pop()
		go func() {
			err = kit.RSAFileEnc(path.(string), key, del)
			util.CheckErr(err)
			<-limits
		}()
	}
	for len(limits) != 0 || !files.IsEmpty() {
		time.Sleep(time.Millisecond * T)
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func DecAction(c *cli.Context) error {
	var del = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")
	key := util.GetInput("Please enter the path of the private key:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}
	for files.Len() > 0 {
		limits <- 1
		path := files.Pop()
		go func() {
			err = kit.RSAFileDec(path.(string), key, del)
			util.CheckErr(err)
			<-limits
		}()
	}
	for len(limits) != 0 || !files.IsEmpty() {
		time.Sleep(time.Millisecond * T)
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func SignAction(*cli.Context) error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the private key:")

	prk, err := ioutil.ReadFile(key)
	if err != nil {
		return err
	}
	data, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}
	signature, err := rsa.RSASign(data, prk)
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
	data, err := ioutil.ReadFile(source)
	if err != nil {
		return err
	}
	ret, err := rsa.RSAVerify(signature, data, puk)
	if err != nil {
		return err
	}
	fmt.Printf("[*]RSA Verify->%t\n", ret)
	return nil
}

func KeyAction(*cli.Context) error {
	val := util.GetInput("The key size is:")
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
