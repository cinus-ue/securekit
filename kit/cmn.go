package kit

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"crypto/rand"
	"errors"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
)

const (
	SktExt    = ".skt"
	SaltLen   = 12
	KeyLen    = 32
	PSizeLen  = 8
	SEPARATOR = string(os.PathSeparator)
)

func VersionCheck(src io.Reader, versionRequirement []byte) error {
	version := make([]byte, len(versionRequirement))
	_, _ = src.Read(version)
	if !bytes.Equal(version, versionRequirement) {
		return errors.New("Inconsistent Version:" + string(version))
	}
	return nil
}

func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateRandomString(digit, symbol bool, length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	digits := "0123456789"
	symbols := "~=+%^*/()[]{}/!@#$?|"
	if digit {
		charset = charset + digits
	}
	if symbol {
		charset = charset + symbols
	}

	for i, b := range bytes {
		bytes[i] = charset[b%byte(len(charset))]
	}
	return string(bytes)
}

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
