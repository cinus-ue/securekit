package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Msg = cli.Command{
	Name:  "msg",
	Usage: "Encrypt messages using the AES algorithm",
	Subcommands: []cli.Command{
		{
			Name:   "enc",
			Usage:  "Encrypt the input data using AES-256-GCM",
			Action: msgEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Decrypt the input data using AES-256-GCM",
			Action: msgDecAction,
		},
	},
}

func msgEncAction(*cli.Context) error {
	source := util.GetInput("Please enter a message:")
	password := util.GetEncPassword()

	ciphertext, err := kit.AESTextEnc(source, password)
	if err != nil {
		return err
	}
	fmt.Printf("\n[*]Output->%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	return nil
}

func msgDecAction(*cli.Context) error {
	source := util.GetInput("Paste the encrypted text here to decrypt:")
	password := util.GetDecPassword()

	plaintext, err := kit.AESTextDec(source, password)
	if err != nil {
		return err
	}
	fmt.Printf("\n[*]Output->%s\n", plaintext)
	return nil
}
