package main

import (
	"os"

	"github.com/cinus-ue/securekit-go/cmd"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "securekit"
	app.Usage = "Data security and protection toolkit"
	app.Version = "1.1.5.20190405"
	app.Commands = []cli.Command{
		cmd.Che,
		cmd.Pas,
		cmd.Wmk,
		cmd.Ren,
		cmd.Aes,
		cmd.Rsa,
		cmd.Msg,
		cmd.Ste,
	}
	err := app.Run(os.Args)
	if err != nil {
		util.CheckErr(err)
	}
}
