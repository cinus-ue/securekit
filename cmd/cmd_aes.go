package cmd

import (
	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Aes = &cli.Command{
	Name:  "aes",
	Usage: "Encrypt files using the AES algorithm",
	Subcommands: []*cli.Command{
		{
			Name:  "enc",
			Usage: "Encrypt the data (file) using AES-256-CTR",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "del",
					Aliases: []string{"d"},
					Usage:   "Delete source file",
				},
			},
			Action: AESEncAction,
		},
		{
			Name:  "dec",
			Usage: "Decrypt the data (file) using AES-256-CTR",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:    "del",
					Aliases: []string{"d"},
					Usage:   "Delete source file",
				},
			},
			Action: AESDecAction,
		},
	},
}

func AESEncAction(c *cli.Context) error {
	var del = c.Bool("del")
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	password := util.GetEncPassword()
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.AESFileEncrypt(path, password, del)
	})
}

func AESDecAction(c *cli.Context) error {
	var del = c.Bool("del")
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), true)
	if err != nil {
		return err
	}
	password := util.GetDecPassword()
	return util.ApplyAllFiles(files, func(path string) error {
		return kit.AESFileDecrypt(path, password, del)
	})
}
