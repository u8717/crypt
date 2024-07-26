package cipherlib

// provides a method to crypt a message with additional data.
// Misuse of this method may lead to a panic.
type Encryptor interface {
	// Encrypts/Decrypts a message, misuse may lead to a panic.
	Crypt(message []byte, additionalData []byte) ([]byte, error)
}

// provides a method to crypt a cipher package.
// Misuse of this method may lead to a panic.
type Decryptor interface {
	// Encrypts/Decrypts a message, misuse may lead to a panic.
	Crypt(cipherpackage []byte) ([]byte, []byte, error)
}
