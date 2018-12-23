package kit

import (
	"bytes"
	"container/list"
	"io"
	"os"
	"path/filepath"
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

func PathScan(path string, dirs bool) (*list.List, error) {
	files := list.New()
	err := filepath.Walk(path, func(path string, f os.FileInfo, err error) error {
		if f == nil {
			return err
		}
		if !dirs && f.IsDir() {
			return nil
		}
		files.PushBack(path)
		return nil
	})
	if dirs {
		files.Remove(files.Front())
	}
	return files, err
}
