package cmd

import (
	"fmt"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Rnm = &cli.Command{
	Name:  "rnm",
	Usage: "Batch rename files and folders",
	Subcommands: []*cli.Command{
		{
			Name:   "enc",
			Usage:  "Rename files and folders using the AES-256-GCM",
			Action: RnmEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Recover files and folders using the AES-256-GCM",
			Action: RnmDecAction,
		},
	},
}

func RnmEncAction(*cli.Context) error {
	source := util.GetInput("Please enter path to scan:")
	files, err := kit.PathScan(source, false)
	if err != nil {
		return err
	}

	password := util.GetEncPassword()
	for files.Len() > 0 {
		path := files.Pop()
		err = kit.Rename(path.(string), password)
		if err != nil {
			return err
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func RnmDecAction(*cli.Context) error {
	source := util.GetInput("Please enter path to scan:")
	files, err := kit.PathScan(source, false)
	if err != nil {
		return err
	}

	password := util.GetDecPassword()
	for files.Len() > 0 {
		path := files.Pop()
		err = kit.Recover(path.(string), password)
		if err != nil {
			return err
		}
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}
