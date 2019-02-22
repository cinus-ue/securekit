package cmd

import (
	"fmt"
	"io/ioutil"
	"strconv"
	"time"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/kit/rsa"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Rsa = cli.Command{
	Name:  "rsa",
	Usage: "Encrypt file using the RSA algorithm",
	Subcommands: []cli.Command{
		{
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Encrypt the data (file) using an RSA public key",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: rsaEncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Decrypt the data (file) using an RSA private key",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: rsaDecAction,
		},
		{
			Name:    "sig",
			Aliases: []string{"s"},
			Usage:   "Sign the data (file) and output the signed result",
			Action:  rsaSignAction,
		},
		{
			Name:    "ver",
			Aliases: []string{"v"},
			Usage:   "Verify the signature using an RSA public key",
			Action:  rsaVerifyAction,
		},
		{
			Name:    "key",
			Aliases: []string{"k"},
			Usage:   "Generate RSA keys",
			Action:  genKeyAction,
		},
	},
}

func rsaEncAction(c *cli.Context) error {
	var delete = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")
	key := util.GetInput("Please enter the path of the public key:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}
	for files.Len() > 0 {
		limits <- 1
		path := files.Pop()
		fmt.Printf("\n[*]processing file:%s ", path.(string))
		go func() {
			err = kit.RSAFileEnc(path.(string), key, delete, limits)
			util.CheckErr(err)
		}()
	}
	for wait {
		time.Sleep(time.Second * 5)
		if len(limits) == 0 && files.IsEmpty() {
			wait = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func rsaDecAction(c *cli.Context) error {
	var delete = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")
	key := util.GetInput("Please enter the path of the private key:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}
	for files.Len() > 0 {
		limits <- 1
		path := files.Pop()
		fmt.Printf("\n[*]processing file:%s ", path.(string))
		go func() {
			err = kit.RSAFileDec(path.(string), key, delete, limits)
			util.CheckErr(err)
		}()
	}
	for wait {
		time.Sleep(time.Second * 5)
		if len(limits) == 0 && files.IsEmpty() {
			wait = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func rsaSignAction(*cli.Context) error {
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

func rsaVerifyAction(*cli.Context) error {
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

func genKeyAction(*cli.Context) error {
	source := util.GetInput("The key size is:")
	size, err := strconv.Atoi(source)
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
