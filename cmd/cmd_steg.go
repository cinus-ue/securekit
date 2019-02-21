package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cinus-ue/securekit-go/kit"
	"github.com/cinus-ue/securekit-go/kit/img"
	"github.com/cinus-ue/securekit-go/util"
	"github.com/urfave/cli"
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

func hideAction(*cli.Context) error {
	imgPath := util.GetInput("Please enter the path of the cover image:")
	msgPath := util.GetInput("Please enter the path of the message file:")

	cover, err := os.Open(imgPath)
	if err != nil {
		return err
	}
	payload, err := ioutil.ReadFile(msgPath)
	if err != nil {
		return err
	}
	out, err := os.Create("stego-out.png")
	if err != nil {
		return err
	}
	defer func() {
		cover.Close()
		out.Close()
	}()

	filename := kit.GetFileName(msgPath)
	payload = assemble(payload, []byte(filename))

	fmt.Printf("[*]Encoding and saving the image...\n")
	err = img.LSBEncoder(out, cover, payload)
	if err != nil {
		return err
	}
	out.Sync()
	fmt.Print("[*]Done.\n")
	return nil
}

func extractAction(*cli.Context) error {
	source := util.GetInput("Please enter the path of the stego file:")

	in, err := os.Open(source)
	if err != nil {
		return err
	}
	payload, err := img.LSBDecoder(in)

	fileNameSize := uint64(payload[5])
	size := payload[6:14]
	buf := bytes.NewBuffer(size)

	var fileSize uint64
	binary.Read(buf, binary.BigEndian, &fileSize)
	filename := string(payload[14 : 14+fileNameSize])

	fmt.Printf("[*]Extracting %s\n", filename)

	out, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer func() {
		in.Close()
		out.Close()
	}()

	msg := payload[14+fileNameSize : 14+fileNameSize+fileSize]
	out.Write(msg)
	out.Sync()

	fmt.Print("[*]Done.\n")
	return nil
}

func assemble(msg []byte, msgFileName []byte) []byte {
	// Format:
	// [magic, 5b] [filename size, 1b] [message size, 8b] [filename] [message...]

	// The magic number will indicate that the message is decoded correctly.
	// The last byte is reserved for future additions. 01 indicates
	// the first version of the format.
	magic := []byte{0xD0, 0x6E, 0xFA, 0xCE, 0x01} // D0 6E FA CE 01

	msgNameSize := []byte{byte(len(msgFileName))}

	// Message Size - Needed to correctly extract the message part
	var tmpSize uint64 = uint64(len(msg))
	msgSize := make([]byte, 8)
	binary.BigEndian.PutUint64(msgSize, uint64(tmpSize))

	// Concatenate the different arrays to msgFull
	msgHead0 := append(magic, msgNameSize...)
	msgHead1 := append(msgHead0, msgSize...)
	msgHeader := append(msgHead1, msgFileName...)
	msgFull := append(msgHeader, msg...)

	return msgFull
}
