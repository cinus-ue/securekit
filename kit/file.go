package kit

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

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

func PathScan(path string, skipDir bool) (*Stack, error) {
	files := NewStack()
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if skipDir && f.IsDir() {
			return nil
		}
		files.Push(path)
		return nil
	})
	return files, err
}

func GetBasePath(path string) string {
	var i int
	if runtime.GOOS == "windows" {
		i = strings.LastIndex(path, "\\")
	} else {
		i = strings.LastIndex(path, "/")
	}
	path = path[0 : i+1]
	return path
}

func GetFileName(path string) string {
	return filepath.Base(path)
}
