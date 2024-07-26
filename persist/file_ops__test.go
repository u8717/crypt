package persist_test

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/u8717/crypt/internal/persist"
)

func TestDefaultFileOps(t *testing.T) {
	var fileOps persist.Ops = persist.File{}
	fileName := "testfile.txt"

	err := fileOps.Create(fileName)
	if err != nil {
		t.Errorf("Error creating file: %v", err)
	}
	defer func() {
		err := fileOps.DeleteFile(fileName)
		if err == nil {
			t.Errorf("Error deleting file: %v", err)
		}
	}()

	_, err = fileOps.ReadLast(fileName)
	if err == nil {
		t.Error("Expected an error when reading an empty file")
	}

	line1 := "Line 1"
	line2 := "Line 2"
	line3 := "Line 3"
	content := line1 + "\n" + line2 + "\n" + line3
	err = fileOps.AppendToFile(fileName, content)
	if err != nil {
		t.Errorf("Error appending to file: %v", err)
	}

	readContent, err := fileOps.ReadWhole(fileName)
	if err != nil {
		t.Errorf("Error reading file: %v", err)
	}
	if string(readContent) != content {
		t.Error("Content mismatch. Expected:", content, "Got:", string(readContent))
	}

	readLineContent, err := fileOps.ReadLast(fileName)
	if err != nil {
		t.Errorf("Error reading last line: %v", err)
	}
	if readLineContent != line3 {
		t.Error("Last line content mismatch. Expected:", line3, "Got:", readLineContent)
	}

	err = fileOps.DeleteFile(fileName)
	if err != nil {
		t.Errorf("Error deleting file: %v", err)
	}
}

func TestWalkDir(t *testing.T) {
	var fileOps persist.Ops = persist.File{}
	testDir := "testdir"
	fileName1 := filepath.Join(testDir, "file1.txt")
	fileName2 := filepath.Join(testDir, "file2.txt")

	// Create test directory and files
	err := os.Mkdir(testDir, os.ModePerm)
	if err != nil {
		t.Fatalf("Error creating test directory: %v", err)
	}
	defer func() {
		err := os.RemoveAll(testDir)
		if err != nil {
			t.Fatalf("Error removing test directory: %v", err)
		}
	}()

	err = fileOps.Create(fileName1)
	if err != nil {
		t.Fatalf("Error creating file1: %v", err)
	}
	defer func() {
		err := fileOps.DeleteFile(fileName1)
		if err != nil {
			t.Fatalf("Error deleting file1: %v", err)
		}
	}()

	err = fileOps.Create(fileName2)
	if err != nil {
		t.Fatalf("Error creating file2: %v", err)
	}
	defer func() {
		err := fileOps.DeleteFile(fileName2)
		if err != nil {
			t.Fatalf("Error deleting file2: %v", err)
		}
	}()
	err = fileOps.Create(fileName1)
	if err == nil {
		t.Fatalf("Exceted an error, file should already exists: %v", err)
	}
	// Test WalkDir
	var foundFiles []string
	err = fileOps.WalkDir(testDir, func(path string, info os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			foundFiles = append(foundFiles, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Error walking directory: %v", err)
	}

	// Assert the result
	expectedFiles := []string{fileName1, fileName2}
	if !reflect.DeepEqual(foundFiles, expectedFiles) {
		t.Errorf("Unexpected files found. Expected: %v, Got: %v", expectedFiles, foundFiles)
	}
}
