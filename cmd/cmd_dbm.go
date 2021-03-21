package cmd

import (
	"fmt"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/kvdb"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Dbm = &cli.Command{
	Name:  "dbm",
	Usage: "Manage securekit database",
	Subcommands: []*cli.Command{
		{
			Name:      "set",
			Usage:     "Set the value at the specified key",
			ArgsUsage: "KEY_NAME VALUE",
			Action:    SetAction,
		},
		{
			Name:      "get",
			Usage:     "Get the value stored in specified key",
			ArgsUsage: "KEY_NAME",
			Action:    GetAction,
		},
		{
			Name:      "del",
			Usage:     "Delete the existing key in database",
			ArgsUsage: "KEY_NAME",
			Action:    DelAction,
		},
		{
			Name:      "dump",
			Usage:     "Export data to JSON format",
			ArgsUsage: "FILE",
			Action:    DumpAction,
		},
		{
			Name:      "keys",
			Usage:     "Search keys with a matching pattern",
			ArgsUsage: "KEY_PATTERN",
			Action:    KeysAction,
		},
	},
}

func SetAction(c *cli.Context) error {
	if c.Args().Len() != 2 {
		util.ArgumentMissing()
		return nil
	}
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	err = db.Set(c.Args().Get(0), c.Args().Get(1))
	if err != nil {
		return err
	}
	fmt.Println("OK")
	return nil
}

func GetAction(c *cli.Context) error {
	if !c.Args().Present() {
		util.ArgumentMissing()
		return nil
	}
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	if value, ok := db.Get(c.Args().Get(0)); ok {
		fmt.Println("Value:", value)
	}
	return nil
}

func DelAction(c *cli.Context) error {
	if !c.Args().Present() {
		util.ArgumentMissing()
		return nil
	}
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	err = db.Delete(c.Args().Get(0))
	if err != nil {
		return err
	}
	fmt.Println("OK")
	return nil
}

func DumpAction(c *cli.Context) error {
	if !c.Args().Present() {
		util.ArgumentMissing()
		return nil
	}
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	data, err := db.Dump()
	if err != nil {
		return err
	}
	return kit.SaveFile(c.Args().Get(0), data)
}

func KeysAction(c *cli.Context) error {
	if !c.Args().Present() {
		util.ArgumentMissing()
		return nil
	}
	db, err := kvdb.InitDB(kvdb.Disk)
	if err != nil {
		return err
	}
	keys, err := db.Keys(c.Args().Get(0))
	if err != nil {
		return err
	}
	for index, value := range keys {
		fmt.Println(index, value)
	}
	return nil
}
