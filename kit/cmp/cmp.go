package cmp

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

const SEPARATOR = string(filepath.Separator)

func Compress(input []byte) []byte {
	var buf bytes.Buffer
	writer := zlib.NewWriter(&buf)
	writer.Write(input)
	writer.Close()
	output := buf.Bytes()
	return output
}

func Decompress(input []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := io.Writer(&buf)
	b := bytes.NewReader(input)
	r, err := zlib.NewReader(b)
	if err != nil {
		return nil, err
	}
	io.Copy(w, r)
	r.Close()
	output := buf.Bytes()
	return output, nil
}

func CompressDir(dir, zipFile string) error {
	fz, err := os.Create(zipFile)
	if err != nil {
		return err
	}
	defer fz.Close()

	w := zip.NewWriter(fz)
	defer w.Close()

	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, v := range files {
		f, err := os.Open(dir + SEPARATOR + v.Name())
		if err != nil {
			return err
		}
		err = compress(f, filepath.Base(dir), w)
		if err != nil {
			return err
		}
	}
	return nil
}

func DecompressDir(zipFile, dir string) error {
	r, err := zip.OpenReader(zipFile)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		path := dir + SEPARATOR + f.Name
		os.MkdirAll(filepath.Dir(path), 0755)
		dest, err := os.Create(path)
		if err != nil {
			return err
		}
		src, err := f.Open()
		if err != nil {
			return err
		}
		_, err = io.Copy(dest, src)
		if err != nil {
			return err
		}
		src.Close()
		dest.Close()
	}
	return nil
}

func compress(file *os.File, prefix string, zw *zip.Writer) error {
	info, _ := file.Stat()
	if info.IsDir() {
		fileInfos, err := file.Readdir(-1)
		if err != nil {
			return err
		}
		for _, fi := range fileInfos {
			f, err := os.Open(file.Name() + SEPARATOR + fi.Name())
			if err != nil {
				return err
			}
			err = compress(f, prefix+SEPARATOR+info.Name(), zw)
			if err != nil {
				return err
			}
		}
	} else {
		header, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		header.Name = prefix + SEPARATOR + header.Name
		writer, err := zw.CreateHeader(header)
		if err != nil {
			return err
		}
		_, err = io.Copy(writer, file)
		if err != nil {
			return err
		}
		file.Close()
	}
	return nil
}
