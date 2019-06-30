package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli"
)

var Msg = cli.Command{
	Name:  "msg",
	Usage: "Encrypt messages using the AES algorithm",
	Subcommands: []cli.Command{
		{
			Name:   "enc",
			Usage:  "Encrypt the input data using AES-256-GCM",
			Action: MsgEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Decrypt the input data using AES-256-GCM",
			Action: MsgDecAction,
		},
	},
}

func MsgEncAction(*cli.Context) error {
	source := util.GetInput("Please enter a message:")
	password := util.GetEncPassword()

	ciphertext, err := kit.AESTextEnc([]byte(source), password)
	if err != nil {
		return err
	}
	fmt.Printf("\n[*]Output->%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	return nil
}

func MsgDecAction(*cli.Context) error {
	source := util.GetInput("Paste the encrypted text here to decrypt:")
	password := util.GetDecPassword()

	ciphertext, err := base64.StdEncoding.DecodeString(source)
	if err != nil {
		return err
	}

	plaintext, err := kit.AESTextDec(ciphertext, password)
	if err != nil {
		return err
	}

	fmt.Printf("\n[*]Output->%s\n", plaintext)
	return nil
}
