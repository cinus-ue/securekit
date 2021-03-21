package cmd

import (
	"fmt"
	"os"
	"strconv"

	"github.com/cinus-ue/securekit/kit/img"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Wmk = &cli.Command{
	Name:      "wmk",
	Usage:     "Create watermark text for images",
	ArgsUsage: "SPACE(60) FONTSIZE(24) OPACITY(0.8) ANGLE(30)",
	Action:    WmkAction,
}

func WmkAction(c *cli.Context) error {
	var args = []float64{60, 24, 0.8, 30}
	if c.Args().Present() {
		for i := 0; i < c.Args().Len(); i++ {
			args[i], _ = strconv.ParseFloat(c.Args().Get(i), 64)
		}
	}
	image, err := os.Open(util.GetInput("Please enter the path of the image:"))
	if err != nil {
		return err
	}
	defer image.Close()
	text := util.GetInput("Please enter the watermark text:")
	wmk, err := img.Watermark(image, text, int(args[0]), args[1], args[2], args[3])
	if err != nil {
		return err
	}
	format := util.GetInput("Select output format[JPG-1/PNG-2]:")
	fmt.Println("[*]Encoding and saving the image...")
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
	fmt.Println("[*]Done.")
	return nil
}
