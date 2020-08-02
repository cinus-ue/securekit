package main

import (
	"os"

	"github.com/cinus-ue/securekit/cmd"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

func main() {
	app := cli.NewApp()
	app.Name = "securekit"
	app.Usage = "Data security and protection toolkit"
	app.Version = "1.1.7.20200802"
	app.Commands = []*cli.Command{
		cmd.Cks,
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
