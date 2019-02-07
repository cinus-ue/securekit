package cmd

import (
	"crypto/aes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
	"io"
	"os"
	"path"
	"strings"
)

const REEXT = ".re"
const MAXLEN = 240

var Rename = cli.Command{
	Name:  "ren",
	Usage: "Batch rename files and folders",
	Subcommands: []cli.Command{
		{
			Name:    "enc",
			Aliases: []string{"e"},
			Usage:   "Rename files and folders using the AES-256-CTR",
			Action:  reEncAction,
		},
		{
			Name:    "dec",
			Aliases: []string{"d"},
			Usage:   "Recover files and folders using the AES-256-CTR",
			Action:  reDecAction,
		},
	},
}

func reEncAction(c *cli.Context) (err error) {

	source := kit.GetInput("Please enter path to scan:")
	files, err := kit.PathScan(source, false)
	kit.CheckErr(err)

	password := kit.GetEncPassword()
	for e := files.Back(); e != nil; e = e.Prev() {
		err = encrypt(e.Value.(string), password)
		kit.CheckErr(err)
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func reDecAction(c *cli.Context) (err error) {

	source := kit.GetInput("Please enter path to scan:")
	files, err := kit.PathScan(source, false)
	kit.CheckErr(err)

	password := kit.GetDecPassword()
	for e := files.Back(); e != nil; e = e.Prev() {
		err = decrypt(e.Value.(string), password)
		kit.CheckErr(err)
	}
	fmt.Print("\n[*]Operation Completed\n")
	return nil
}

func encrypt(source string, password []byte) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, REEXT) == 0 {
		return nil
	}

	fmt.Printf("\n[*]processing file:%s", source)

	dk, _, err := kit.DeriveKey(password, []byte(password), 32)
	kit.CheckErr(err)

	block, err := kit.AESCipher(dk)
	kit.CheckErr(err)

	plaintext := []byte(kit.GetFileName(source))
	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	_, err = io.ReadFull(rand.Reader, iv)
	kit.CheckErr(err)

	stream := kit.AESCTR(block, iv[:])
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	basePath := kit.GetBasePath(source)
	name := basePath + base64.URLEncoding.EncodeToString(ciphertext) + REEXT
	if len(name) > MAXLEN {
		return errors.New("the file name is too long")
	}

	err = os.Rename(source, name)
	kit.CheckErr(err)
	return nil
}

func decrypt(source string, password []byte) error {
	suffix := path.Ext(source)
	if strings.Compare(suffix, REEXT) != 0 {
		return nil
	}

	fmt.Printf("\n[*]processing file:%s", source)

	ciphertext, err := base64.URLEncoding.DecodeString(kit.GetFileName(source[:len(source)-len(REEXT)]))
	kit.CheckErr(err)

	dk, _, err := kit.DeriveKey(password, []byte(password), 32)
	kit.CheckErr(err)

	block, err := kit.AESCipher(dk)
	kit.CheckErr(err)

	iv := ciphertext[:aes.BlockSize]
	stream := kit.AESCTR(block, iv)
	var plaintext = []byte(ciphertext[aes.BlockSize:])
	stream.XORKeyStream(plaintext, ciphertext[aes.BlockSize:])

	basePath := kit.GetBasePath(source)
	name := basePath + string(plaintext)
	err = os.Rename(source, name)
	kit.CheckErr(err)
	return nil
}
