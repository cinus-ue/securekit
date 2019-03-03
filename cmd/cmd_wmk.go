package cmd

import (
	"fmt"
	"os"

	"github.com/cinus-ue/securekit-go/kit/img"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
)

var Wmk = cli.Command{
	Name:   "wmk",
	Usage:  "Add a text watermark to an image",
	Action: wmkAction,
}

func wmkAction(*cli.Context) error {
	path := util.GetInput("Please enter the path of the image:")
	text := util.GetInput("Please enter the watermark text:")
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()

	wmk, err := img.Watermark(in, text, 0, 13)
	if err != nil {
		return err
	}
	format := util.GetInput("Select output format[JPG-1/PNG-2]:")
	fmt.Printf("[*]Encoding and saving the image...\n")
	switch format {
	case "1":
		err = wmk.SaveJPG("wmk-out.jpg")
		if err != nil {
			return err
		}
	case "2":
		err = wmk.SavePNG("wmk-out.png")
		if err != nil {
			return err
		}
	}
	fmt.Print("[*]Done.\n")
	return nil
}
