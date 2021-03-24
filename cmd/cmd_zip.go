package cmd

import (
	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Zip = &cli.Command{
	Name:  "zip",
	Usage: "Compress (zip) and uncompress (unzip) files",
	Subcommands: []*cli.Command{
		{
			Name:      "archive",
			Usage:     "Package and compress (archive) files",
			ArgsUsage: "PATH ZIP_FILE",
			Action:    ArchiveZipAction,
		},
		{
			Name:      "extract",
			Usage:     "Extract compressed files in a ZIP archive",
			ArgsUsage: "ZIP_FILE PATH",
			Action:    ExtractZipAction,
		},
	},
}

func ArchiveZipAction(c *cli.Context) error {
	if c.Args().Len() != 2 {
		util.ArgumentMissing()
		return nil
	}
	return kit.CompressDir(c.Args().Get(0), c.Args().Get(1))
}

func ExtractZipAction(c *cli.Context) error {
	if c.Args().Len() != 2 {
		util.ArgumentMissing()
		return nil
	}
	return kit.DecompressDir(c.Args().Get(0), c.Args().Get(1))
}
