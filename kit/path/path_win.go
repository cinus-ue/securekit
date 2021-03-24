// +build windows

package path

import "syscall"

func HidePath(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(name, syscall.FILE_ATTRIBUTE_HIDDEN)
}

func ShowPath(path string) error {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	return syscall.SetFileAttributes(name, syscall.FILE_ATTRIBUTE_NORMAL)
}
