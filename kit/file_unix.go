// +build !windows

package kit

import (
	"os"
	"strings"
)

func HidePath(path string) error {
	return os.Rename(path, "."+path)
}

func ShowPath(path string) error {
	return os.Rename(path, strings.Trim(path, "."))
}
