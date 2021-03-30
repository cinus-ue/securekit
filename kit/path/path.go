package path

import (
	"bytes"
	"container/list"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const Separator = string(os.PathSeparator)

func SaveFile(path string, data []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, bytes.NewReader(data))
	if err != nil {
		return err
	}
	return nil
}

func ValidateFile(file string) bool {
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return false
	}
	return true
}

func Scan(path string, skipDir bool) (*list.List, error) {
	files := list.New()
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if skipDir && f.IsDir() {
			return nil
		}
		files.PushBack(path)
		return nil
	})
	return files, err
}

func BasePath(path string) string {
	var i = strings.LastIndex(path, Separator)
	return path[0 : i+1]
}

func Name(path string) string {
	return filepath.Base(path)
}
