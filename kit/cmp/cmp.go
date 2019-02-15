package cmp

import (
	"bytes"
	"compress/zlib"
	"io"
)

// compress the message
func Compress(input []byte) []byte {
	var buf bytes.Buffer
	compr := zlib.NewWriter(&buf)
	compr.Write(input)
	compr.Close()
	output := buf.Bytes()
	return output
}

// decompress the message
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
