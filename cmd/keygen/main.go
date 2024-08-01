package main

import (
	"fmt"
	"os"

	"github.com/u8717/crypt/libcipher"
)

func main() {
	// Generate a key using the keygen package
	encodedKey, err := libcipher.GenerateKey(64)
	if err != nil {
		fmt.Println("Error generating key:", err)
		os.Exit(1)
	}

	fmt.Println(encodedKey)
}
