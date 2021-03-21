package cmd

import (
	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Rnm = &cli.Command{
	Name:  "rnm",
	Usage: "Batch rename files and folders",
	Subcommands: []*cli.Command{
		{
			Name:   "enc",
			Usage:  "Rename files and folders",
			Action: RnmEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Recover files and folders",
			Action: RnmDecAction,
		},
	},
}

func RnmEncAction(*cli.Context) error {
	files, err := kit.PathScan(util.GetInput("Please enter path to scan:"), false)
	if err != nil {
		return err
	}
	password := util.GetEncPassword()
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	err = util.ApplyOrderedFiles(files, func(path string) error {
		return kit.Rename(path, password, db)
	})
	return err
}

func RnmDecAction(*cli.Context) error {
	files, err := kit.PathScan(util.GetInput("Please enter path to scan:"), false)
	if err != nil {
		return err
	}
	password := util.GetDecPassword()
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	err = util.ApplyOrderedFiles(files, func(path string) error {
		return kit.Recover(path, password, db)
	})
	return err
}
