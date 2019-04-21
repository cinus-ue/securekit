package cmd

import (
	"fmt"
	"time"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Aes = cli.Command{
	Name:  "aes",
	Usage: "Encrypt files using the AES algorithm",
	Subcommands: []cli.Command{
		{
			Name:  "enc",
			Usage: "Encrypt the input data using AES-256-CTR",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: AESEncAction,
		},
		{
			Name:  "dec",
			Usage: "Decrypt the input data using AES-256-CTR",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: AESDecAction,
		},
	},
}

func AESEncAction(c *cli.Context) error {
	var delete = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}
	password := util.GetEncPassword()
	for files.Len() > 0 {
		limits <- 1
		path := files.Pop()
		go func() {
			err = kit.AESFileEnc(path.(string), password, delete)
			util.CheckErr(err)
			<-limits
		}()
	}
	for wait {
		time.Sleep(time.Second * T)
		if len(limits) == 0 && files.IsEmpty() {
			wait = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func AESDecAction(c *cli.Context) error {
	var delete = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")

	files, err := kit.PathScan(source, true)
	if err != nil {
		return err
	}

	password := util.GetDecPassword()
	for files.Len() > 0 {
		limits <- 1
		path := files.Pop()
		go func() {
			err = kit.AESFileDec(path.(string), password, delete)
			util.CheckErr(err)
			<-limits
		}()
	}
	for wait {
		time.Sleep(time.Second * T)
		if len(limits) == 0 && files.IsEmpty() {
			wait = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}
