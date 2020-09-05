package kit

import (
	"bytes"
	"errors"
	"io"
)

const (
	SktExt   = ".skt"
	SaltLen  = 12
	KeyLen   = 32
	PSizeLen = 8
)

func VersionCheck(src io.Reader, versionRequirement []byte) error {
	version := make([]byte, len(versionRequirement))
	src.Read(version)
	if !bytes.Equal(version, versionRequirement) {
		return errors.New("Inconsistent Version:" + string(version))
	}
	return nil
}
