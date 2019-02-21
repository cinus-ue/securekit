package main

import (
	"fmt"
	"os"

	"github.com/cinus-ue/securekit-go/cmd"
	"github.com/urfave/cli"
)

func main() {
	app := cli.NewApp()
	app.Name = "securekit"
	app.Usage = "Data security and protection toolkit"
	app.Version = "1.1.3.20190221"
	app.Commands = []cli.Command{
		cmd.Md5,
		cmd.Sha,
		cmd.Rename,
		cmd.Aes,
		cmd.Rsa,
		cmd.Text,
		cmd.Steg,
	}
	err := app.Run(os.Args)
	if err != nil{
		fmt.Printf("\n[*]ERROR:%s", err.Error())
	}
}
