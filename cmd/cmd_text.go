package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
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

func textEncAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter a message:")
	password := kit.GetEncPassword()
	dk, salt, err := kit.DeriveKey(password, nil, 32)
	kit.CheckErr(err)
	block, err := kit.AESCipher(dk)
	kit.CheckErr(err)
	aesgcm, err := kit.AESGCM(block)
	kit.CheckErr(err)
	ciphertext := aesgcm.Seal(nil, salt, []byte(source), nil)
	// Append the salt to the end of file
	ciphertext = append(ciphertext, salt...)
	fmt.Printf("\n[*]Output Data->%s\n", base64.StdEncoding.EncodeToString(ciphertext))
	return nil
}

func textDecAction(c *cli.Context) (err error) {
	source := kit.GetInput("Paste the encrypted message here to decrypt:")
	password := kit.GetDecPassword()
	ciphertext, err := base64.StdEncoding.DecodeString(source)
	kit.CheckErr(err)
	nonce := ciphertext[len(ciphertext)-12:]
	dk, _, err := kit.DeriveKey(password, nonce, 32)
	kit.CheckErr(err)
	block, err := kit.AESCipher(dk)
	kit.CheckErr(err)
	aesgcm, err := kit.AESGCM(block)
	kit.CheckErr(err)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext[:len(ciphertext)-12], nil)
	kit.CheckErr(err)
	fmt.Printf("\n[*]Output Data->%s\n", plaintext)
	return nil
}
