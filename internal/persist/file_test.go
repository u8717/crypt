package persist_test

import (
	"os"
	"reflect"
	"testing"

	"github.com/u8717/crypt/internal/persist"
)

func TestDefaultFileOps(t *testing.T) {
	var fileOps persist.Ops
	fileOps, err := persist.NewFileOps(".")
	if err != nil {
		t.Fatal(err)
	}
	fileName := "testfile.txt"
	err = fileOps.Create(fileName)
	if err != nil {
		t.Errorf("Error creating file: %v", err)
	}
	defer func() {
		err := fileOps.Delete(fileName)
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
	content := []byte(line1 + "\n" + line2 + "\n" + line3)
	err = fileOps.AppendTo(fileName, content)
	if err != nil {
		t.Errorf("Error appending to file: %v", err)
	}

	readContent, err := fileOps.ReadWhole(fileName)
	if err != nil {
		t.Errorf("Error reading file: %v", err)
	}
	if string(readContent) != string(content) {
		t.Error("Content mismatch. Expected:", content, "Got:", string(readContent))
	}

	readLineContent, err := fileOps.ReadLast(fileName)
	if err != nil {
		t.Errorf("Error reading last line: %v", err)
	}
	if string(readLineContent) != line3 {
		t.Error("Last line content mismatch. Expected:", line3, "Got:", readLineContent)
	}

	err = fileOps.Delete(fileName)
	if err != nil {
		t.Errorf("Error deleting file: %v", err)
	}
}

func TestWalkDir(t *testing.T) {
	var fileOps persist.Ops
	testDir := "testdir"
	fileOps, err := persist.NewFileOps(testDir)
	if err != nil {
		t.Fatal(err)
	}
	fileName1 := "file1.txt"
	fileName2 := "file2.txt"

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
		err := fileOps.Delete(fileName1)
		if err != nil {
			t.Fatalf("Error deleting file1: %v", err)
		}
	}()

	err = fileOps.Create(fileName2)
	if err != nil {
		t.Fatalf("Error creating file2: %v", err)
	}
	defer func() {
		err := fileOps.Delete(fileName2)
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
	foundFiles, err = fileOps.List()
	if err != nil {
		t.Fatalf("Error walking directory: %v", err)
	}

	// Assert the result
	expectedFiles := []string{fileName1, fileName2}
	if !reflect.DeepEqual(foundFiles, expectedFiles) {
		t.Errorf("Unexpected files found. Expected: %v, Got: %v", expectedFiles, foundFiles)
	}
}
