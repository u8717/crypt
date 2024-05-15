package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
)

func main() {
	// Generate 32 random bytes (256 bits) for the key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		fmt.Println("Error generating key:", err)
		os.Exit(1)
	}

	// Encode the key in hexadecimal format for easier storage and sharing
	encodedKey := hex.EncodeToString(key)
	fmt.Println(encodedKey)
}
