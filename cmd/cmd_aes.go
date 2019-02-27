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
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Encrypt the input data using AES-256-CTR",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: aesEncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Decrypt the input data using AES-256-CTR",
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: aesDecAction,
		},
	},
}

func aesEncAction(c *cli.Context) error {
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
		fmt.Printf("\n[*]processing file:%s ", path.(string))
		go func() {
			err = kit.AESFileEnc(path.(string), password, delete, limits)
			util.CheckErr(err)
		}()
	}
	for wait {
		time.Sleep(time.Second * 3)
		if len(limits) == 0 && files.IsEmpty() {
			wait = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func aesDecAction(c *cli.Context) error {
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
		fmt.Printf("\n[*]processing file:%s ", path.(string))
		go func() {
			err = kit.AESFileDec(path.(string), password, delete, limits)
			util.CheckErr(err)
		}()
	}
	for wait {
		time.Sleep(time.Second * 3)
		if len(limits) == 0 && files.IsEmpty() {
			wait = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}
