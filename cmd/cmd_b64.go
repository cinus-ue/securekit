package cmd

import (
	"encoding/base64"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
)

var Base64 = cli.Command{
	Name:  "b64",
	Usage: "Base64 encoder and decoder",
	Subcommands: []cli.Command{
		{
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Encode the input data to a Base64 string",
			Action:  base64EncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Decode the data from a Base64 string",
			Action:  base64DecAction,
		},
	},
}

func base64EncAction(c *cli.Context) (err error) {
	text := kit.GetInput("Please enter a message:")
	ret := base64.StdEncoding.EncodeToString([]byte(text))
	fmt.Printf("[*]Base64->%s\n", ret)
	return nil
}

func base64DecAction(c *cli.Context) (err error) {
	text := kit.GetInput("Paste the base64 string here to decode:")
	ret, err := base64.StdEncoding.DecodeString(text)
	kit.CheckErr(err)
	fmt.Printf("[*]Base64->%s\n", string(ret))
	return nil
}
