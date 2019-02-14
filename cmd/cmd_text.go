package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Text = cli.Command{
	Name:  "text",
	Usage: "Encrypt messages using the AES algorithm",
	Subcommands: []cli.Command{
		{
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Encrypt the input data using AES-256-GCM",
			Action:  textEncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Decrypt the input data using AES-256-GCM",
			Action:  textDecAction,
		},
	},
}

func textEncAction(*cli.Context)error{
	source := util.GetInput("Please enter a message:")
	password := util.GetEncPassword()

	ciphertext,err := kit.AESTextEnc(source,password)
	if err != nil{
		return err
	}
	fmt.Printf("\n[*]Output Data->%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	return nil
}

func textDecAction(*cli.Context)error {
	source := util.GetInput("Paste the encrypted text here to decrypt:")
	password := util.GetDecPassword()

    plaintext,err := kit.AESTextDec(source,password)
	if err != nil{
		return err
	}
	fmt.Printf("\n[*]Output Data->%s\n", plaintext)
	return nil
}
