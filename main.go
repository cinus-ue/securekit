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
	app.Version = "1.2.6.20210626"
	app.Commands = []*cli.Command{
		cmd.Cks,
		cmd.Dbm,
		cmd.Dsm,
		cmd.Lsb,
		cmd.Pgp,
		cmd.Pss,
		cmd.Rnm,
	}
	err := app.Run(os.Args)
	util.CheckErr(err)
}
