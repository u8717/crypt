# crypt (WiP)

A collection of tools and helpers for handling sensitive data. As this is a personal project, please carefully review the code for correctness and security before using it.

**Note:** If you happen to see and review this code, you are welcome to leave your feedback.

## libcipher

### AES-CBC-HMAC

Located in `libcipher`, this module implements encryption and integrity protection using AES-CBC cipher mode and HMAC.

- **Secure Encryption:** Utilizes AES-CBC mode for robust encryption.
- **Data Integrity:** Employs HMAC (HMAC-SHA256 or similar) to ensure data hasn't been tampered with.
- **Associated Data Support:** Allows inclusion of unencrypted associated data (AD) that needs authentication along with the ciphertext.
- **Customizable HMAC:** The HMAC algorithm can be configured during setup.

**Message Format:**
The encrypted message package has the following structure:
`[MAC | AD-Length (2 bytes) | AD | Initialization Vector | Block 1 | Block 2 | ...]`

#### When to Use AES-CBC-HMAC

- You need both encryption and integrity protection.
- Avoiding nonce collisions presents challenges in your use case (e.g., high-volume systems, distributed environments, or scenarios with persistent storage of encrypted data).

#### Considerations for AES-CBC-HMAC

- **Memory Constraints:** Since the HMAC calculation requires the entire cipher to be in memory, it might not be ideal for very large messages.
- **Key Management:** Ensure secure key generation, storage, and rotation practices. Separate encryption and integrity keys are essential.
- **Nonce/IV Generation:** This implementation recommends using `rand.Reader`.

### AES-GCM

AES-GCM implements encryption, integrity, and authenticity using AES-GCM mode via a single operation.

**Message Format:**
`[Nonce] | AD-Length (2 bytes) | AD | [Ciphertext] | [Authentication Tag]`

#### When to Use AES-GCM

- When dealing with non-persisted, short-lived, and not distributed data.
- When performance is critical.
- When the encrypted content-size per entry is not very large.
- When you are able to prevent nonce reuse.

#### Considerations for AES-GCM

- **Memory Constraints:** The current implementation requires the entire cipher to be in memory, but this should be fine since it is not useful for large messages anyway.
- **Key Management:** Ensure secure key generation, storage, and rotation practices. Separate encryption and integrity keys are not needed.
- **Nonce/IV Generation:** This implementation recommends using `rand.Reader`.

## libstore

The `libstore` package provides a simple and secure key-value store with encryption and integrity features.

### Components

- **file.go**: Implements file-based storage operations.
- **file_test.go**: Contains tests for the file-based storage operations.
- **ops.go**: Defines the operations for the key-value store.
- **store_cryptor.go**: Integrates `libcipher` for encrypting and decrypting store operations.

### Key Features

- **File-Based Storage**: Stores key-value pairs in a file system.
- **Encryption**: Uses `libcipher` for encrypting stored values.
- **Data Integrity**: Ensures stored data has not been tampered with using HMAC.

### Example Usage

Here is a brief example of how to use the `libstore` package:

```go
package main

import (
	"crypto/sha256"
	"fmt"
	"log"

	"github.com/u8717/crypt/libstore"
)

func main() {
	ops, err := libstore.NewFileOps(".")
	if err != nil {
		log.Fatalf("Failed to initialize file operations: %v", err)
	}
	manager, err := libstore.NewManager(ops, []byte("encryptionKey"), []byte("integrityKey"), sha256.New)
	if err != nil {
		log.Fatalf("Failed to initialize cryptographic manager: %v", err)
	}

	// Create a new key
	if err := manager.Create("exampleKey"); err != nil {
		log.Fatalf("Failed to create key: %v", err)
	}

	// Append a value to the key
	if err := manager.AppendTo("exampleKey", []byte("exampleValue")); err != nil {
		log.Fatalf("Failed to append value: %v", err)
	}

	// Read the last value of the key
	value, err := manager.ReadLast("exampleKey")
	if err != nil {
		log.Fatalf("Failed to read value: %v", err)
	}
	fmt.Printf("Read value: %s\n", value)

	// List all keys
	keys, err := manager.List()
	if err != nil {
		log.Fatalf("Failed to list keys: %v", err)
	}
	fmt.Printf("Keys: %v\n", keys)
}
```

### Considerations

- **Key Management**: Ensure secure key generation, storage, and rotation practices.
- **Concurrency**: Be mindful of concurrent access to the file-based storage to avoid race conditions.

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests.
