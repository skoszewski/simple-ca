// MIT License
//
// Copyright (c) 2026 Slawomir Koszewski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package simpleca

import (
	"cmp"
	"errors"
	"os"
)

// PrivateGroupWriteEnv is the environment variable that, when it is set, gives the group of a
// CA directory the reading and writing of its private files and directories.
const PrivateGroupWriteEnv = "SIMPLE_CA_PRIVATE_GROUP_WRITE"

// PrivateMode returns the mode of a private file: 0660 when SIMPLE_CA_PRIVATE_GROUP_WRITE is
// set, else 0600.
func PrivateMode() os.FileMode {
	if os.Getenv(PrivateGroupWriteEnv) != "" {
		return 0o660
	}
	return 0o600
}

// DirMode returns the mode of a directory made in a CA directory: 0770 when
// SIMPLE_CA_PRIVATE_GROUP_WRITE is set, else 0750.
func DirMode() os.FileMode {
	if os.Getenv(PrivateGroupWriteEnv) != "" {
		return 0o770
	}
	return 0o750
}

// CreatePrivateFile opens the file at path with flag, creating it of PrivateMode whatever the
// umask; an existing file keeps its mode and owner, and is an error when flag has O_EXCL.
func CreatePrivateFile(path string, flag int) (*os.File, error) {
	f, err := os.OpenFile(path, flag|os.O_CREATE|os.O_EXCL, PrivateMode())
	switch {
	case err == nil:
		if err := f.Chmod(PrivateMode()); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	case errors.Is(err, os.ErrExist) && flag&os.O_EXCL == 0:
		return os.OpenFile(path, flag, 0)
	}
	return nil, err
}

// WritePrivateFile writes data to the file at path, as CreatePrivateFile creates it.
func WritePrivateFile(path string, data []byte) error {
	f, err := CreatePrivateFile(path, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return cmp.Or(err, f.Close())
}

// MkdirAll makes the directory at path and its missing parents, the directory of DirMode
// whatever the umask; an existing directory is left as it is.
func MkdirAll(path string) error {
	if info, err := os.Stat(path); err == nil && info.IsDir() {
		return nil
	}
	if err := os.MkdirAll(path, DirMode()); err != nil {
		return err
	}
	return os.Chmod(path, DirMode())
}
