package main

import (
	"github.com/cinus-ue/securekit-go/cmd"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
	"os"
)

func main() {
	app := cli.NewApp()
	app.Name = "securekit"
	app.Usage = "Data security and protection toolkit"
	app.Version = "1.1.0.20190118"
	app.Commands = []cli.Command{
		cmd.Md5,
		cmd.Sha,
		cmd.Hex,
		cmd.Base64,
		cmd.Rename,
		cmd.Aes,
		cmd.Rsa,
		cmd.Text,
		cmd.Steg,
	}
	err := app.Run(os.Args)
	kit.CheckErr(err)
}
