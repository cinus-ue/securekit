package cmd

import (
	"encoding/base64"
	"fmt"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Msg = &cli.Command{
	Name:  "msg",
	Usage: "Encrypt messages using the AES algorithm",
	Subcommands: []*cli.Command{
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
	message := util.GetInput("Please enter a message:")
	password := util.GetEncPassword()
	ciphertext, err := kit.SktMsgEncrypt([]byte(message), password)
	if err != nil {
		return err
	}
	fmt.Printf("\n[*]Encrypted Output->%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	return nil
}

func MsgDecAction(*cli.Context) error {
	message := util.GetInput("Paste the encrypted text here to decrypt:")
	password := util.GetDecPassword()
	ciphertext, err := base64.StdEncoding.DecodeString(message)
	if err != nil {
		return err
	}
	plaintext, err := kit.SktMsgDecrypt(ciphertext, password)
	if err != nil {
		return err
	}
	fmt.Printf("\n[*]Decrypted Output->%s\n", plaintext)
	return nil
}
