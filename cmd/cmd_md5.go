package cmd

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Md5 = cli.Command{
	Name:  "md5",
	Usage: "MD5 Hash Generator",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "text,t",
			Usage: "Calculate MD5 hash of a string",
		},
		&cli.BoolFlag{
			Name:  "file,f",
			Usage: "Calculate MD5 hash of a file",
		},
	},
	Action: md5Action,
}

func md5Action(c *cli.Context) error {
	var file = c.Bool("file")
	switch {
	case file:
		source := util.GetInput("Please enter the path of the source file:")
		ret32, err := kit.Checksum(source, md5.New())
		if err != nil {
			return err
		}
		fmt.Printf("[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
		fmt.Printf("\n[*]Md5-32->%s\n", hex.EncodeToString(ret32))
	default:
		text := util.GetInput("Please enter a message:")
		ret32 := kit.Md532([]byte(text))
		fmt.Printf("[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
		fmt.Printf("\n[*]Md5-32->%s\n", hex.EncodeToString(ret32))
	}
	return nil
}
