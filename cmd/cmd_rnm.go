package cmd

import (
	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Rnm = &cli.Command{
	Name:  "rnm",
	Usage: "Obfuscate file names and directory names",
	Subcommands: []*cli.Command{
		{
			Name:   "enc",
			Usage:  "Rename file names and directory names",
			Action: RnmEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Recover file names and directory names",
			Action: RnmDecAction,
		},
	},
}

func RnmEncAction(*cli.Context) error {
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), false)
	if err != nil {
		return err
	}
	password := util.GetEncPassword()
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	return util.ApplyOrderedFiles(files, func(path string) error {
		return kit.Rename(path, password, db)
	})
}

func RnmDecAction(*cli.Context) error {
	files, err := path.Scan(util.GetInput("Please enter path to scan:"), false)
	if err != nil {
		return err
	}
	password := util.GetDecPassword()
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	return util.ApplyOrderedFiles(files, func(path string) error {
		return kit.Recover(path, password, db)
	})
}
