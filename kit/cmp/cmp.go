package cmp

import (
	"bytes"
	"compress/zlib"
	"io"
)

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
