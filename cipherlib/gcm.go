package cipherlib

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
)

// cryptorGCM implements the Encryptor and Decryptor interfaces using AES-GCM.
type cryptorGCM struct {
	gcm       cipher.AEAD
	rand      io.Reader
	blocksize func() int
}

// Encryption mode.
type encryptorGCM cryptorGCM

// Decryption mode.
type decryptorGCM cryptorGCM

// NewGCMEncryptor creates a new Encryptor using AES-GCM with the given key.
func NewGCMEncryptor(encyptionKey []byte, rand io.Reader) (Encryptor, error) {
	cryptor, err := newGCMCryptor(encyptionKey)
	if err != nil {
		return nil, err
	}
	cryptor.rand = rand

	return (encryptorGCM)(cryptor), nil
}

// NewGCMDecryptor creates a new Decryptor using AES-GCM with the given key.
func NewGCMDecryptor(encyptionKey []byte) (Decryptor, error) {
	cryptor, err := newGCMCryptor(encyptionKey)
	if err != nil {
		return nil, err
	}

	return (decryptorGCM)(cryptor), nil
}

func newGCMCryptor(encyptionKey []byte) (cryptorGCM, error) {
	const minKeySize = 16
	// Check key sizes.
	if len(encyptionKey) < minKeySize {
		return cryptorGCM{}, EncryptionKeyError("encryption key too short")
	}
	block, err := aes.NewCipher(encyptionKey)
	if err != nil {
		return cryptorGCM{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return cryptorGCM{}, err
	}
	return cryptorGCM{gcm: gcm, blocksize: block.BlockSize}, nil
}

// Crypt encrypts the given message using AES-GCM with the provided additional data.
func (e encryptorGCM) Crypt(message []byte, additionalData []byte) ([]byte, error) {
	if message == nil {
		return nil, MessageError("message was nil")
	}
	if uint64(len(message)) > uint64(((1<<32)-2)*e.blocksize()) {
		return nil, MessageError("crypto/cipherlib: message too large for GCM")
	}
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(e.rand, nonce); err != nil {
		return nil, err
	}

	// Allocate space for the cipherpackage
	cipherpackage := make([]byte, additionalDataHeaderLength+len(additionalData)+len(nonce)+len(message)+e.gcm.Overhead())

	// Copy nonce to the beginning of the cipherpackage
	copy(cipherpackage, nonce)

	// Copy additional data length and additional data into cipherpackage
	binary.BigEndian.PutUint16(cipherpackage[len(nonce):len(nonce)+additionalDataHeaderLength], uint16(len(additionalData)))
	copy(cipherpackage[len(nonce)+additionalDataHeaderLength:len(nonce)+additionalDataHeaderLength+len(additionalData)], additionalData)

	// Encrypt the message
	e.gcm.Seal(cipherpackage[len(nonce)+additionalDataHeaderLength+len(additionalData):len(nonce)+additionalDataHeaderLength+len(additionalData)], nonce, message, additionalData)

	return cipherpackage, nil
}

// Crypt decrypts the given cipher package using AES-GCM.
func (d decryptorGCM) Crypt(cipherpackage []byte) ([]byte, []byte, error) {
	nonceSize := d.gcm.NonceSize()

	if len(cipherpackage) < nonceSize+additionalDataHeaderLength {
		return nil, nil, errors.New("cipherpackage too short")
	}

	// Extract the nonce
	nonce := cipherpackage[:nonceSize]

	// Extract the additional data length
	additionalDataLength := binary.BigEndian.Uint16(cipherpackage[nonceSize : nonceSize+additionalDataHeaderLength])

	if len(cipherpackage) < nonceSize+additionalDataHeaderLength+int(additionalDataLength) {
		return nil, nil, errors.New("cipherpackage too short for additional data")
	}

	// Extract the additional data
	additionalData := cipherpackage[nonceSize+additionalDataHeaderLength : nonceSize+additionalDataHeaderLength+int(additionalDataLength)]

	// Extract the ciphertext
	ciphertext := cipherpackage[nonceSize+additionalDataHeaderLength+int(additionalDataLength):]

	// Decrypt the ciphertext
	plaintext, err := d.gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, nil, err
	}

	return plaintext, additionalData, nil
}
