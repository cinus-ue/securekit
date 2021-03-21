package cmd

import (
	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Vis = &cli.Command{
	Name:  "vis",
	Usage: "Hide the files and folders",
	Subcommands: []*cli.Command{
		{
			Name:      "hide",
			Usage:     "Hide the files and folders",
			ArgsUsage: "PATH",
			Action:    HidePathAction,
		},
		{
			Name:      "show",
			Usage:     "Show the files and folders",
			ArgsUsage: "PATH",
			Action:    ShowPathAction,
		},
	},
}

func HidePathAction(c *cli.Context) error {
	if !c.Args().Present() {
		util.ArgumentMissing()
		return nil
	}
	return kit.HidePath(c.Args().Get(0))
}

func ShowPathAction(c *cli.Context) error {
	if !c.Args().Present() {
		util.ArgumentMissing()
		return nil
	}
	return kit.ShowPath(c.Args().Get(0))
}
