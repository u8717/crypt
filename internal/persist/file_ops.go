package persist

import (
	"bufio"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
)

type Ops interface {
	Create(fileName string) error
	ReadWhole(fileName string) ([]byte, error)
	ReadLast(fileName string) (string, error)
	AppendToFile(fileName string, content string) error
	DeleteFile(fileName string) error
	WalkDir(dir string, fn func(path string, info fs.DirEntry, err error) error) error
}

type File struct{}

func (fops File) Create(fileName string) error {
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		return fmt.Errorf("file %s already exists", fileName)
	}
	file, err := os.Create(fileName)
	defer func() {
		err := file.Close()
		if err != nil {
			slog.Debug("closing file", "error", err)
		}
	}()
	return err
}

func (fops File) ReadWhole(fileName string) ([]byte, error) {
	return os.ReadFile(fileName)
}

func (fops File) ReadLast(filename string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			slog.Debug("closing file", "error", err)
		}
	}()

	scanner := bufio.NewScanner(file)
	var lastLine string

	for scanner.Scan() {
		lastLine = scanner.Text()
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}
	if lastLine == "" {
		return "", fmt.Errorf("File is empty for name %s", filename)
	}
	return lastLine, nil
}

func (fops File) AppendToFile(fileName string, content string) error {
	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer func() {
		err := file.Close()
		if err != nil {
			slog.Debug("closing file", "error", err)
		}
	}()

	stat, err := file.Stat()
	if err != nil {
		return err
	}

	if stat.Size() > 0 {
		content = "\n" + content
	}

	_, err = file.WriteString(content)
	return err
}

func (fops File) DeleteFile(fileName string) error {
	return os.Remove(fileName)
}

func (fops File) WalkDir(dir string, fn func(path string, info fs.DirEntry, err error) error) error {
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		return fn(path, d, err)
	})
}
