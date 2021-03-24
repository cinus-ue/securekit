package cmd

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/cinus-ue/securekit/kit/img"
	"github.com/cinus-ue/securekit/kit/path"
	"github.com/cinus-ue/securekit/util"
	"github.com/urfave/cli/v2"
)

var Lsb = &cli.Command{
	Name:  "lsb",
	Usage: "LSB (Least Significant Bit) based steganography",
	Subcommands: []*cli.Command{
		{
			Name:   "enc",
			Usage:  "Encode the data (file) inside an image",
			Action: LsbEncAction,
		},
		{
			Name:   "dec",
			Usage:  "Decode the data (file) from an image",
			Action: LsbDecAction,
		},
	},
}

func LsbEncAction(*cli.Context) error {
	image, err := os.Open(util.GetInput("Please enter the path of the cover image:"))
	if err != nil {
		return err
	}
	msgPath := util.GetInput("Please enter the path of the message file:")
	payload, err := ioutil.ReadFile(msgPath)
	if err != nil {
		return err
	}
	out, err := os.Create("stego-out.png")
	if err != nil {
		return err
	}
	defer func() {
		image.Close()
		out.Close()
	}()
	filename := path.GetFileName(msgPath)
	payload = assemble(payload, []byte(filename))
	fmt.Println("[*]Encoding and saving the image...")
	err = img.LSBEncoder(out, image, payload)
	if err != nil {
		return err
	}
	out.Sync()
	fmt.Println("[*]Done.")
	return nil
}

func LsbDecAction(*cli.Context) error {
	in, err := os.Open(util.GetInput("Please enter the path of the stego file:"))
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
	fmt.Println("[*]Extracting:", filename)
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
	fmt.Println("[*]Done.")
	return nil
}

func assemble(msg []byte, fileName []byte) []byte {
	// Format:
	// [magic, 5b] [filename size, 1b] [message size, 8b] [filename] [message...]

	// The magic number will indicate that the message is decoded correctly.
	// The last byte is reserved for future additions. 01 indicates
	// the first version of the format.
	magic := []byte{0xD0, 0x6E, 0xFA, 0xCE, 0x01} // D0 6E FA CE 01

	msgNameSize := []byte{byte(len(fileName))}

	// Message Size - Needed to correctly extract the message part
	var tmpSize = uint64(len(msg))
	msgSize := make([]byte, 8)
	binary.BigEndian.PutUint64(msgSize, tmpSize)

	// Concatenate the different arrays to msgFull
	msgHead0 := append(magic, msgNameSize...)
	msgHead1 := append(msgHead0, msgSize...)
	msgHeader := append(msgHead1, fileName...)
	msgFull := append(msgHeader, msg...)

	return msgFull
}
