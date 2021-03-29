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
	app.Version = "1.2.1.20210329"
	app.Commands = []*cli.Command{
		cmd.Aes,
		cmd.Cks,
		cmd.Dbm,
		cmd.Lsb,
		cmd.Msg,
		cmd.Pss,
		cmd.Rnm,
		cmd.Rsa,
	}
	err := app.Run(os.Args)
	util.CheckErr(err)
}
