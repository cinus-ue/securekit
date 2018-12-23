package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
	"io/ioutil"
	"os"
	"path/filepath"
)

var Steg = cli.Command{
	Name:  "steg",
	Usage: "Hide Secret Message inside an Image",
	Subcommands: []cli.Command{
		{
			Name:    "hide",
			Aliases: []string{"h"},
			Usage:   "Hide the data (file) inside an image",
			Action:  hideAction,
		},
		{
			Name:    "extract",
			Aliases: []string{"e"},
			Usage:   "Extract the data (file) from an image",
			Action:  extractAction,
		},
	},
}

func hideAction(c *cli.Context) (err error) {
	imgPath := kit.GetInput("Please enter the path of the cover image:")
	msgPath := kit.GetInput("Please enter the path of the message file:")

	coverFile, err := os.Open(imgPath)
	kit.CheckErr(err)
	defer coverFile.Close()

	payload, err := ioutil.ReadFile(msgPath)
	kit.CheckErr(err)

	outFile, err := os.Create("stego-out.png")
	defer outFile.Close()

	filename := filepath.Base(msgPath)
	payload = assemble(payload, filename)

	fmt.Printf("[*]Encoding and saving the image...\n")
	err = kit.ImgEncode(outFile, coverFile, payload)
	kit.CheckErr(err)
	outFile.Sync()
	fmt.Print("[*]Done.\n")
	return nil
}

func extractAction(c *cli.Context) (err error) {
	source := kit.GetInput("Please enter the path of the stego file:")

	infile, err := os.Open(source)
	kit.CheckErr(err)

	payload, err := kit.ImgDecode(infile)

	fileNameSize := uint64(payload[5])
	size := payload[6:14]
	buf := bytes.NewBuffer(size)

	var fileSize uint64
	binary.Read(buf, binary.BigEndian, &fileSize)
	filename := string(payload[14 : 14+fileNameSize])

	fmt.Printf("[*]Extracting %s\n", filename)

	outFile, err := os.Create(filename)
	kit.CheckErr(err)
	defer outFile.Close()

	msg := payload[14+fileNameSize : 14+fileNameSize+fileSize]
	outFile.Write(msg)
	outFile.Sync()

	fmt.Print("[*]Done.\n")
	return nil
}

func assemble(msg []byte, msgFileName string) []byte {
	// Format:
	// [magic, 5b] [filename size, 1b] [message size, 8b] [filename] [message...]

	// The magic number will indicate that the message is decoded correctly.
	// The last byte is reserved for future additions. 01 indicates
	// the first version of the format.
	magic := []byte{0xD0, 0x6E, 0xFA, 0xCE, 0x01} // D0 6E FA CE 01

	msgFileName_b := []byte(msgFileName)

	msgNameSize := []byte{byte(len(msgFileName_b))}

	// Message Size - Needed to correctly extract the message part
	var tmpSize uint64 = uint64(len(msg))
	msgSize := make([]byte, 8)
	binary.BigEndian.PutUint64(msgSize, uint64(tmpSize))

	// Concatenate the different arrays to msgFull
	msgHead0 := append(magic, msgNameSize...)
	msgHead1 := append(msgHead0, msgSize...)
	msgHeader := append(msgHead1, msgFileName_b...)
	msgFull := append(msgHeader, msg...)

	return msgFull
}
