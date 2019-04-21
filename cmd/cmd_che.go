package cmd

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Che = cli.Command{
	Name:  "che",
	Usage: "MD5 & SHA checksum utility",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "text,t",
			Usage: "Generate hash (checksum) value for a string",
		},
		&cli.BoolFlag{
			Name:  "file,f",
			Usage: "Generate hash (checksum) value for a file",
		},
	},
	Action: CheAction,
}

func CheAction(c *cli.Context) error {
	var file = c.Bool("file")

	switch {
	case file:
		source := util.GetInput("Please enter the path of the source file:")
		fmt.Print("Hash method:\n  1--Md5\n  2--SHA1\n  3--SHA256\n  4--SHA384\n  5--SHA512\n")
		algo := util.GetInput("select the appropriate number [1-5]:")
		switch algo {
		case "1":
			ret32, err := kit.Checksum(source, md5.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
			fmt.Printf("\n[*]Md5-32->%s\n", hex.EncodeToString(ret32))
		case "2":
			ret1, err := kit.Checksum(source, sha1.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA1->%s\n", hex.EncodeToString(ret1))
		case "3":
			ret256, err := kit.Checksum(source, sha256.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA256->%s\n", hex.EncodeToString(ret256))
		case "4":
			ret384, err := kit.Checksum(source, sha512.New384())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA384->%s\n", hex.EncodeToString(ret384))
		case "5":
			ret512, err := kit.Checksum(source, sha512.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA512->%s\n", hex.EncodeToString(ret512))
		}
	default:
		text := util.GetInput("Please enter a message:")
		ret32 := kit.Md532([]byte(text))
		fmt.Printf("[*]Md5-16->%s", hex.EncodeToString(ret32)[8:24])
		fmt.Printf("\n[*]Md5-32->%s", hex.EncodeToString(ret32))
		ret1 := kit.SHA1([]byte(text))
		fmt.Printf("\n[*]SHA1--->%s", hex.EncodeToString(ret1))
		ret256 := kit.SHA256([]byte(text))
		fmt.Printf("\n[*]SHA256->%s", hex.EncodeToString(ret256))
		ret384 := kit.SHA384([]byte(text))
		fmt.Printf("\n[*]SHA384->%s", hex.EncodeToString(ret384))
		ret512 := kit.SHA512([]byte(text))
		fmt.Printf("\n[*]SHA512->%s\n", hex.EncodeToString(ret512))
	}
	return nil
}
