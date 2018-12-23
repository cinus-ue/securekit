package cmd

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"github.com/cinus-ue/securekit-go/kit"
	"github.com/urfave/cli"
	"io"
	"os"
	"path"
	"strings"
	"sync"
)

const AESEXT = ".aes"

var limits = make(chan int, 3)
var waitGroup = sync.WaitGroup{}

var Aes = cli.Command{
	Name:  "aes",
	Usage: "Encrypt file using the AES algorithm",
	Subcommands: []cli.Command{
		{
			Name:                   "enc",
			Aliases:                []string{"e"},
			Usage:                  "Encrypt the input data using AES-256-CTR",
			UseShortOptionHandling: true,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: aesEncAction,
		},
		{
			Name:                   "dec",
			Aliases:                []string{"d"},
			Usage:                  "Decrypt the input data using AES-256-CTR",
			UseShortOptionHandling: true,
			Flags: []cli.Flag{
				&cli.BoolFlag{
					Name:  "del,d",
					Usage: "Delete source file",
				},
			},
			Action: aesDecAction,
		},
	},
}

func aesEncAction(c *cli.Context) (err error) {
	var delete = c.Bool("del")
	source := kit.GetInput("Please enter the path of the files:")

	files, err := kit.PathScan(source, false)
	kit.CheckErr(err)

	password := kit.GetEncPassword()
	for e := files.Front(); e != nil; e = e.Next() {
		limits <- 1
		waitGroup.Add(1)
		go fileEncrypt(e.Value.(string), password, delete)
	}
	waitGroup.Wait()
	fmt.Print("\n[*]Operation Completed\n")
	return nil

}

func aesDecAction(c *cli.Context) (err error) {
	var delete = c.Bool("del")
	source := kit.GetInput("Please enter the path of the files:")

	files, err := kit.PathScan(source, false)
	kit.CheckErr(err)

	password := kit.GetDecPassword()
	for e := files.Front(); e != nil; e = e.Next() {
		limits <- 1
		waitGroup.Add(1)
		go fileDecrypt(e.Value.(string), password, delete)
	}
	waitGroup.Wait()
	fmt.Print("\n[*]Operation Completed\n")
	return nil

}

func fileEncrypt(source string, password []byte, delete bool) {
	defer func() {
		<-limits
		waitGroup.Done()
	}()
	suffix := path.Ext(source)
	if strings.Compare(suffix, AESEXT) == 0 {
		return
	}

	fmt.Printf("\n[*]processing file:%s ", source)
	inFile, err := os.Open(source)
	kit.CheckErr(err)
	dk, _, err := kit.DeriveKey(password, []byte(password), 32)
	kit.CheckErr(err)
	block, err := kit.AESCipher(dk)
	kit.CheckErr(err)
	iv := make([]byte, aes.BlockSize)
	_, err = io.ReadFull(rand.Reader, iv)
	kit.CheckErr(err)
	stream := kit.AESCTR(block, iv)

	outFile, err := os.OpenFile(source+AESEXT, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	kit.CheckErr(err)
	defer outFile.Close()
	outFile.Write(iv)
	writer := &cipher.StreamWriter{S: stream, W: outFile}
	_, err = io.Copy(writer, inFile)
	kit.CheckErr(err)
	inFile.Close()

	if delete {
		err := os.Remove(source)
		kit.CheckErr(err)
	}
}

func fileDecrypt(source string, password []byte, delete bool) {
	defer func() {
		<-limits
		waitGroup.Done()
	}()
	suffix := path.Ext(source)
	if strings.Compare(suffix, AESEXT) != 0 {
		return
	}

	fmt.Printf("\n[*]processing file:%s ", source)
	inFile, err := os.Open(source)
	kit.CheckErr(err)
	dk, _, err := kit.DeriveKey(password, []byte(password), 32)
	kit.CheckErr(err)
	block, err := kit.AESCipher(dk)
	kit.CheckErr(err)
	iv := make([]byte, aes.BlockSize)
	inFile.Read(iv)
	stream := kit.AESCTR(block, iv)

	outFile, err := os.OpenFile(source[:len(source)-len(AESEXT)], os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	kit.CheckErr(err)
	defer outFile.Close()
	reader := &cipher.StreamReader{S: stream, R: inFile}
	_, err = io.Copy(outFile, reader)
	kit.CheckErr(err)
	inFile.Close()

	if delete {
		err := os.Remove(source)
		kit.CheckErr(err)
	}
}
