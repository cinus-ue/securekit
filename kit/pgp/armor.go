package pgp

import (
	"errors"
	"golang.org/x/crypto/openpgp/armor"
	"strings"
)

func Unarmor(input string) (*armor.Block, error) {
	io := strings.NewReader(input)
	b, err := armor.Decode(io)
	if err != nil {
		return nil, errors.New("openpgp: unable to armor")
	}
	return b, nil
}
