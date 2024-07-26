package cipherlib

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// cryptorGCM implements the Encryptor and Decryptor interfaces using AES-GCM.
type cryptorGCM struct {
	gcm  cipher.AEAD
	rand io.Reader
}

// Encryption mode.
type encryptorGCM cryptorGCM

// Decryption mode.
type decryptorGCM cryptorGCM

// NewGCMEncryptor creates a new Encryptor using AES-GCM with the given key.
func NewGCMEncryptor(key []byte, rand io.Reader) (Encryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return encryptorGCM{gcm: gcm, rand: rand}, nil
}

// NewGCMDecryptor creates a new Decryptor using AES-GCM with the given key.
func NewGCMDecryptor(key []byte) (Decryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return decryptorGCM{gcm: gcm}, nil
}

// Crypt encrypts the given message using AES-GCM with the provided additional data.
func (e encryptorGCM) Crypt(message []byte, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(e.rand, nonce); err != nil {
		return nil, err
	}
	ciphertext := e.gcm.Seal(nonce, nonce, message, additionalData)

	return ciphertext, nil
}

// Crypt decrypts the given cipher package using AES-GCM.
func (d decryptorGCM) Crypt(cipherpackage []byte) ([]byte, []byte, error) {
	nonceSize := d.gcm.NonceSize()
	if len(cipherpackage) < nonceSize {
		return nil, nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := cipherpackage[:nonceSize], cipherpackage[nonceSize:]
	plaintext, err := d.gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, nil, err
	}

	return plaintext, nil, nil
}
