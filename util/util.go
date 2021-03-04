package util

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/cinus-ue/securekit/kit"
	"github.com/cinus-ue/securekit/kit/sema"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/text/encoding/simplifiedchinese"
)

var semaphore = sema.NewSemaphore(runtime.NumCPU())

type FileFunc func(path string) error

type Charset string

const (
	UTF8    = Charset("UTF-8")
	GB18030 = Charset("GB18030")
)

func GetEncPassword() []byte {
	fmt.Print("Enter password:")
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	fmt.Print("\nConfirm password:")
	password2, _ := terminal.ReadPassword(int(syscall.Stdin))
	if !validatePassword(password, password2) {
		fmt.Print("\nPasswords do not match. Please try again.\n")
		return GetEncPassword()
	}
	return password
}

func GetDecPassword() []byte {
	fmt.Print("Enter password:")
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	if len(password) == 0 {
		fmt.Print("\nIncorrect password. Please try again.\n")
		return GetDecPassword()
	}
	return password
}

func validatePassword(password1 []byte, password2 []byte) bool {
	if len(password1) == 0 || len(password2) == 0 {
		return false
	}
	if !bytes.Equal(password1, password2) {
		return false
	}
	return true
}

func GetInput(s string) string {
	var input string
	f := bufio.NewReader(os.Stdin)
	for {
		fmt.Print(s)
		input, _ = f.ReadString('\n')
		input = strings.TrimSpace(input)
		if len(input) == 0 {
			continue
		} else {
			return input
		}
	}
}

func ConvertByte2String(byte []byte, charset Charset) string {
	var str string
	switch charset {
	case GB18030:
		var decodeBytes, _ = simplifiedchinese.GB18030.NewDecoder().Bytes(byte)
		str = string(decodeBytes)
	case UTF8:
		fallthrough
	default:
		str = string(byte)
	}
	return str
}

func ApplyOrderedFiles(files *kit.Stack, fn FileFunc) error {
	for files.Len() > 0 {
		path := files.Pop()
		printPath(path.(string))
		err := fn(path.(string))
		if err != nil {
			return err
		}
	}
	OperationCompleted()
	return nil
}

func ApplyAllFiles(files *kit.Stack, fn FileFunc) error {
	for files.Len() > 0 {
		path := files.Pop()
		semaphore.Add(1)
		go func() {
			defer semaphore.Done()
			printPath(path.(string))
			err := fn(path.(string))
			if err != nil {
				fmt.Printf("\n[*]Error: %s", err.Error())
				files.Clear()
			}
		}()
	}
	semaphore.Wait()
	OperationCompleted()
	return nil
}

func printPath(path string) {
	path = filepath.ToSlash(path)
	arr := strings.Split(path, "/")
	if len(arr) > 2 {
		path = arr[len(arr)-2] + "/" + arr[len(arr)-1]
	}
	fmt.Printf("\n[*]processing file:%s", path)
}

func OperationCompleted() {
	fmt.Printf("\n[*]Operation Completed\n")
}

func ArgumentMissing() {
	fmt.Println("Error: required arguments not provided.")
	fmt.Println("For more information try --help")
}

func CheckErr(err error) {
	if err != nil {
		panic(err)
	}
}
