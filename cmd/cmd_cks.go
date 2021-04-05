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
	Usage: "Generate text & file checksum",
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
	ArgsUsage: "TEXT/FILE_PATH",
	Action:    CksAction,
}

func CksAction(c *cli.Context) error {
	if c.Bool("file") {
		var path = c.Args().Get(0)
		if path == "" {
			path = util.GetInput("Please enter the path of the source file:")
		}
		fmt.Print("Hash Methods:\n  1--Md5\n  2--SHA1\n  3--SHA256\n  4--SHA384\n  5--SHA512\n")
		algo := util.GetInput("select the appropriate number [1-5]:")
		switch algo {
		case "1":
			sum32, err := kit.HashSum(path, md5.New())
			if err != nil {
				return err
			}
			fmt.Println("[*]Md5-16->", hex.EncodeToString(sum32)[8:24])
			fmt.Println("[*]Md5-32->", hex.EncodeToString(sum32))
		case "2":
			sum1, err := kit.HashSum(path, sha1.New())
			if err != nil {
				return err
			}
			fmt.Println("[*]SHA1->", hex.EncodeToString(sum1))
		case "3":
			sum256, err := kit.HashSum(path, sha256.New())
			if err != nil {
				return err
			}
			fmt.Println("[*]SHA256->", hex.EncodeToString(sum256))
		case "4":
			sum384, err := kit.HashSum(path, sha512.New384())
			if err != nil {
				return err
			}
			fmt.Println("[*]SHA384->", hex.EncodeToString(sum384))
		case "5":
			sum512, err := kit.HashSum(path, sha512.New())
			if err != nil {
				return err
			}
			fmt.Println("[*]SHA512->", hex.EncodeToString(sum512))
		}
	} else {
		var text = c.Args().Get(0)
		if text == "" {
			text = util.GetInput("Please enter a message:")
		}
		data := []byte(text)
		sum32 := kit.Md532(data)
		fmt.Println("[*]Md5-16->", hex.EncodeToString(sum32)[8:24])
		fmt.Println("[*]Md5-32->", hex.EncodeToString(sum32))
		fmt.Println("[*]SHA1--->", hex.EncodeToString(kit.SHA1(data)))
		fmt.Println("[*]SHA256->", hex.EncodeToString(kit.SHA256(data)))
		fmt.Println("[*]SHA384->", hex.EncodeToString(kit.SHA384(data)))
		fmt.Println("[*]SHA512->", hex.EncodeToString(kit.SHA512(data)))
	}
	return nil
}
