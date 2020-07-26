package main

import (
	"os"

	"github.com/cinus-ue/securekit/cmd"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "securekit"
	app.Usage = "Data security and protection toolkit"
	app.Version = "1.1.6.20200726"
	app.Commands = []cli.Command{
		cmd.Ckm,
		cmd.Pss,
		cmd.Wmk,
		cmd.Rnm,
		cmd.Aes,
		cmd.Rsa,
		cmd.Msg,
		cmd.Stg,
	}
	err := app.Run(os.Args)
	if err != nil {
		util.CheckErr(err)
	}
}
