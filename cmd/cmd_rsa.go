package cmd

import (
	"errors"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
	"io/ioutil"
	"path"
	"strconv"
	"strings"
)

const RSAEXT = ".rsa"

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
			Name:    "sign",
			Aliases: []string{"s"},
			Usage:   "Sign the data (file) and output the signed result",
			Action:  rsaSignAction,
		},
		{
			Name:    "verify",
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

func rsaEncAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path of the file:")
	key := kit.GetInput("Please enter the path of the public key:")

	puk, err := ioutil.ReadFile(key)
	kit.CheckErr(err)

	suffix := path.Ext(source)
	if strings.Compare(suffix, RSAEXT) == 0 {
		return errors.New("the file has been encrypted")
	}

	data, err := ioutil.ReadFile(source)
	kit.CheckErr(err)
	fmt.Printf("[*]processing file:%s ", source)
	ciphertext, err := kit.RSAEncrypt(data, puk)
	err = kit.SaveFile(source+RSAEXT, ciphertext)
	kit.CheckErr(err)
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func rsaDecAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path of the file:")
	key := kit.GetInput("Please enter the path of the private key:")

	prk, err := ioutil.ReadFile(key)
	kit.CheckErr(err)

	suffix := path.Ext(source)
	if strings.Compare(suffix, RSAEXT) != 0 {
		return errors.New("the file is not an encrypted file")
	}

	data, err := ioutil.ReadFile(source)
	kit.CheckErr(err)
	fmt.Printf("[*]processing file:%s ", source)
	plaintext, err := kit.RSADecrypt(data, prk)
	err = kit.SaveFile(source[:len(source)-len(RSAEXT)], plaintext)
	kit.CheckErr(err)
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func rsaSignAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path of the file:")
	key := kit.GetInput("Please enter the path of the private key:")

	prk, err := ioutil.ReadFile(key)
	kit.CheckErr(err)
	data, err := ioutil.ReadFile(source)
	kit.CheckErr(err)
	signature, err := kit.RSASign(data, prk)
	fmt.Printf("[*]Signature->%s\n", signature)
	return nil

}

func rsaVerifyAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path of the file:")
	signature := kit.GetInput("Please enter the signature:")
	key := kit.GetInput("Please enter the path of the public key:")

	puk, err := ioutil.ReadFile(key)
	kit.CheckErr(err)
	data, err := ioutil.ReadFile(source)
	kit.CheckErr(err)
	ret, err := kit.RSAVerify(signature, data, puk)
	kit.CheckErr(err)
	fmt.Printf("[*]RSA Verify->%t\n", ret)
	return nil

}

func genKeyAction(c *cli.Context) (err error) {
	source := kit.GetInput("The key size is:")
	size, err := strconv.Atoi(source)
	kit.CheckErr(err)

	privateKey, err := kit.GenerateRSAKey(size)
	kit.CheckErr(err)

	err = kit.SaveRSAKey(privateKey)
	kit.CheckErr(err)

	fmt.Print("Keys Generated!\n")
	return nil
}
