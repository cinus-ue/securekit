package util

import (
	"bufio"
	"bytes"
	"container/list"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

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
	fmt.Print("\n")
	return password
}

func GetDecPassword() []byte {
	fmt.Print("Enter password:")
	password, _ := terminal.ReadPassword(int(syscall.Stdin))
	if len(password) == 0 {
		fmt.Print("\nIncorrect password. Please try again.\n")
		return GetDecPassword()
	}
	fmt.Print("\n")
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

func ApplyOrderedFiles(files *list.List, fn FileFunc) error {
	for path := files.Back(); path != nil; path = path.Prev() {
		printPath(path.Value.(string))
		err := fn(path.Value.(string))
		if err != nil {
			return err
		}
	}
	OperationCompleted()
	return nil
}

func ApplyAllFiles(files *list.List, fn FileFunc) error {
	for path := files.Back(); path != nil; path = path.Prev() {
		var value = path.Value.(string)
		semaphore.Add(1)
		go func() {
			defer semaphore.Done()
			printPath(value)
			err := fn(value)
			if err != nil {
				fmt.Println("[*]Error:", err.Error())
				files.Init()
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
	fmt.Println("[*]processing file:", path)
}

func OperationCompleted() {
	fmt.Println("[*]Operation Completed")
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
