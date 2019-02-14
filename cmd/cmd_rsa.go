package cmd

import (
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
	"io/ioutil"
	"strconv"
)

var Rsa = cli.Command{
	Name:  "rsa",
	Usage: "Encrypt file using the RSA algorithm",
	Subcommands: []cli.Command{
		{
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Encrypt the data (file) using an RSA public key",
			Action:  rsaEncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Decrypt the data (file) using an RSA private key",
			Action:  rsaDecAction,
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

func rsaEncAction(*cli.Context)error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the public key:")

	fmt.Printf("[*]processing file:%s ", source)
	err := kit.RSAFileEnc(source, key)
	if err != nil{
		return err
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func rsaDecAction(*cli.Context)error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the private key:")

	fmt.Printf("[*]processing file:%s ", source)
	err := kit.RSAFileDec(source, key)
	if err != nil{
		return err
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func rsaSignAction(*cli.Context)error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the private key:")

	prk, err := ioutil.ReadFile(key)
	if err != nil{
		return err
	}
	data, err := ioutil.ReadFile(source)
	if err != nil{
		return err
	}
	signature, err := kit.RSASign(data, prk)
	fmt.Printf("[*]Signature->%s\n", signature)
	return nil
}

func rsaVerifyAction(*cli.Context)error {
	source := util.GetInput("Please enter the path of the source file:")
	key := util.GetInput("Please enter the path of the public key:")
	signature := util.GetInput("Please enter the signature:")

	puk, err := ioutil.ReadFile(key)
	if err != nil{
		return err
	}
	data, err := ioutil.ReadFile(source)
	if err != nil{
		return err
	}
	ret, err := kit.RSAVerify(signature, data, puk)
	if err != nil{
		return err
	}
	fmt.Printf("[*]RSA Verify->%t\n", ret)
	return nil
}

func genKeyAction(*cli.Context)error {
	source := util.GetInput("The key size is:")
	size, err := strconv.Atoi(source)
	if err != nil{
		return err
	}
	privateKey, err := kit.GenerateRSAKey(size)
	if err != nil{
		return err
	}
	err = kit.SaveRSAKey(privateKey)
	if err != nil{
		return err
	}
	fmt.Print("Keys Generated!\n")
	return nil
}
