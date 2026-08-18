package testfixture

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// MaxBytes exceeds every retained fixture while bounding review-controlled input
const MaxBytes = 1 << 20

func Read(rootPath, name string) ([]byte, error) {
	if filepath.Base(name) != name {
		return nil, errors.New("fixture name is not a base name")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, errors.Join(err, root.Close())
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.Join(errors.New("fixture is not a regular file"), err, file.Close(), root.Close())
	}
	data, readErr := io.ReadAll(io.LimitReader(file, MaxBytes+1))
	closeErr := errors.Join(file.Close(), root.Close())
	if len(data) > MaxBytes {
		return nil, errors.Join(fmt.Errorf("fixture exceeds %d bytes", MaxBytes), readErr, closeErr)
	}
	return data, errors.Join(readErr, closeErr)
}
