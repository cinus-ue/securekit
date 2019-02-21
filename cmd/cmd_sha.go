package cmd

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Sha = cli.Command{
	Name:  "sha",
	Usage: "SHA Hash Generator",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:  "text,t",
			Usage: "Calculate SHA hash of a string",
		},
		&cli.BoolFlag{
			Name:  "file,f",
			Usage: "Calculate SHA hash of a file",
		},
	},
	Action: shaAction,
}

func shaAction(c *cli.Context) error {
	var file = c.Bool("file")
	switch {
	case file:
		source := util.GetInput("Please enter the path of the source file:")
		fmt.Print("algorithm:\n  1--SHA1\n  2--SHA256\n  3--SHA384\n  4--SHA512\n")
		algo := util.GetInput("select the appropriate number [1-4]:")
		switch algo {
		case "1":
			ret1, err := kit.Checksum(source, sha1.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA1->%s", hex.EncodeToString(ret1))
		case "2":
			ret256, err := kit.Checksum(source, sha256.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA256->%s", hex.EncodeToString(ret256))
		case "3":
			ret384, err := kit.Checksum(source, sha512.New384())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA384->%s", hex.EncodeToString(ret384))
		case "4":
			ret512, err := kit.Checksum(source, sha512.New())
			if err != nil {
				return err
			}
			fmt.Printf("[*]SHA512->%s\n", hex.EncodeToString(ret512))
		}
	default:
		text := util.GetInput("Please enter a message:")
		ret1 := kit.SHA1([]byte(text))
		fmt.Printf("[*]SHA1->%s", hex.EncodeToString(ret1))
		ret256 := kit.SHA256([]byte(text))
		fmt.Printf("\n[*]SHA256->%s", hex.EncodeToString(ret256))
		ret384 := kit.SHA384([]byte(text))
		fmt.Printf("\n[*]SHA384->%s", hex.EncodeToString(ret384))
		ret512 := kit.SHA512([]byte(text))
		fmt.Printf("\n[*]SHA512->%s\n", hex.EncodeToString(ret512))
	}
	return nil
}
