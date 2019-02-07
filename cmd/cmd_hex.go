package cmd

import (
	"encoding/hex"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
)

var Hex = cli.Command{
	Name:  "hex",
	Usage: "Hex encoder and decoder",
	Subcommands: []cli.Command{
		{
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Encode the input data to a Hex encoded string",
			Action:  hexEncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Decode the data from a Hex encoded string",
			Action:  hexDecAction,
		},
	},
}

func hexEncAction(c *cli.Context) (err error) {
	text := kit.GetInput("Please enter a message:")
	ret := hex.EncodeToString([]byte(text))
	fmt.Printf("[*]Hex->%s\n", ret)
	return nil
}

func hexDecAction(c *cli.Context) (err error) {
	text := kit.GetInput("Paste the hexadecimal string here to decode:")
	ret, err := hex.DecodeString(text)
	kit.CheckErr(err)
	fmt.Printf("[*]Hex->%s\n", string(ret))
	return nil
}
