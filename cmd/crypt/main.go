package main

import (
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/u8717/crypt/cipherlib"
)

func main() {
	// CLI Flags.
	keyFile := flag.String("key", "", "Path to the key file (required)")
	flag.Parse()

	if len(*keyFile) == 0 {
		fmt.Fprintln(os.Stderr, "Error: key file was not provided")
		os.Exit(1)
	}

	// Check for both mode and input.
	if flag.NArg() < 2 {
		fmt.Fprintln(os.Stderr, "Error: mode (e/d) and input text are required as command-line arguments.")
		os.Exit(1)
	}

	mode := flag.Arg(0)
	if mode != "e" && mode != "d" {
		fmt.Fprintln(os.Stderr, "Error: invalid mode. Please use 'e' for encryption or 'd' for decryption.")
		os.Exit(1)
	}

	input := []byte(flag.Arg(1))

	// Key Loading.
	encryptionKey, integrityKey := loadBasicKey(keyFile)

	// Crypt Operation.
	var output string
	if mode == "e" {
		output = encrypt(encryptionKey, integrityKey, input)
	} else {
		output = decrypt(encryptionKey, integrityKey, input)
	}

	fmt.Println(output)
}

func loadBasicKey(keyFile *string) ([]byte, []byte) {
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading key file:", err)
		os.Exit(1)
	}
	// Split the key into encryption and integrity keys.
	encryptionKey := key[:16]
	integrityKey := key[16:32]
	return encryptionKey, integrityKey
}

func decrypt(encryptionKey []byte, integrityKey []byte, input []byte) string {
	decryptor, err := cipherlib.NewCBCHMACDecryptor(encryptionKey, integrityKey, sha256.New)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error initializing decryptor:", err)
		os.Exit(1)
	}
	decodetInput, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decoding input to byte array:", err)
		os.Exit(1)
	}
	// Additional data is not supported in the cli yet.
	output, _, err := decryptor.Crypt(decodetInput)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error decrypting file:", err)
		os.Exit(1)
	}

	return string(output)
}

func encrypt(encryptionKey []byte, integrityKey []byte, input []byte) string {
	encryptor, err := cipherlib.NewCBCHMACEncryptor(encryptionKey, integrityKey, sha256.New)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error initializing encryptor:", err)
		os.Exit(1)
	}
	output, err := encryptor.Crypt(input, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error encrypting file:", err)
		os.Exit(1)
	}

	return base64.StdEncoding.EncodeToString(output)
}
