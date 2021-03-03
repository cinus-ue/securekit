package cmd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Cks = &cli.Command{
	Name:  "cks",
	Usage: "MD5 & SHA checksum utility",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "text",
			Aliases: []string{"t"},
			Usage:   "Generate hash (checksum) value for a string",
		},
		&cli.BoolFlag{
			Name:    "file",
			Aliases: []string{"f"},
			Usage:   "Generate hash (checksum) value for a file",
		},
	},
	Action: CksAction,
}

func CksAction(c *cli.Context) error {
	var file = c.Bool("file")

	switch {
	case file:
		path := util.GetInput("Please enter the path of the source file:")
		fmt.Print("Hash method:\n  1--Md5\n  2--SHA1\n  3--SHA256\n  4--SHA384\n  5--SHA512\n")
		algo := util.GetInput("select the appropriate number [1-5]:")
		switch algo {
		case "1":
			ret32, err := kit.Checksum(path, md5.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
			fmt.Printf("\n[*]Md5-32->%s\n", hex.EncodeToString(ret32))
		case "2":
			ret1, err := kit.Checksum(path, sha1.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA1->%s\n", hex.EncodeToString(ret1))
		case "3":
			ret256, err := kit.Checksum(path, sha256.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA256->%s\n", hex.EncodeToString(ret256))
		case "4":
			ret384, err := kit.Checksum(path, sha512.New384())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA384->%s\n", hex.EncodeToString(ret384))
		case "5":
			ret512, err := kit.Checksum(path, sha512.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA512->%s\n", hex.EncodeToString(ret512))
		}
	default:
		message := util.GetInput("Please enter a message:")
		data := []byte(message)
		ret32 := kit.Md532(data)
		fmt.Printf("[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
		fmt.Printf("\n[*]Md5-32->%s", hex.EncodeToString(ret32))
		fmt.Printf("\n[*]SHA1--->%s", hex.EncodeToString(kit.SHA1(data)))
		fmt.Printf("\n[*]SHA256->%s", hex.EncodeToString(kit.SHA256(data)))
		fmt.Printf("\n[*]SHA384->%s", hex.EncodeToString(kit.SHA384(data)))
		fmt.Printf("\n[*]SHA512->%s\n", hex.EncodeToString(kit.SHA512(data)))
	}
	return nil
}
