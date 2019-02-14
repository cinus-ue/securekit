package cmd

import (
	"fmt"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var limits = make(chan int, 3)
var status = true

var Aes = cli.Command{
	Name:  "aes",
	Usage: "Encrypt file using the AES algorithm",
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

func aesEncAction(c *cli.Context)error {
	var delete = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")

	files, err := kit.PathScan(source, true)
	if err != nil{
		return err
	}
	password := util.GetEncPassword()
	for e := files.Front(); e != nil; e = e.Next() {
		limits <- 1
		fmt.Printf("\n[*]processing file:%s ", e.Value.(string))
		go kit.AESFileEnc(e.Value.(string), password, delete, limits)
	}
	for status {
		if len(limits) == 0 {
			status = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func aesDecAction(c *cli.Context)error {
	var delete = c.Bool("del")
	source := util.GetInput("Please enter path to scan:")

	files, err := kit.PathScan(source, true)
	if err != nil{
		return err
	}

	password := util.GetDecPassword()
	for e := files.Front(); e != nil; e = e.Next() {
		limits <- 1
		fmt.Printf("\n[*]processing file:%s ", e.Value.(string))
		go kit.AESFileDec(e.Value.(string), password, delete, limits)
	}
	for status {
		if len(limits) == 0 {
			status = false
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}
