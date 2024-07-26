package cipherlib

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// GCMEncryptorDecryptor implements the Encryptor and Decryptor interfaces using AES-GCM.
type GCMEncryptorDecryptor struct {
	gcm cipher.AEAD
}

// NewGCMEncryptorDecryptor creates a new GCMEncryptorDecryptor with the given key.
func NewGCMEncryptorDecryptor(key []byte) (*GCMEncryptorDecryptor, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &GCMEncryptorDecryptor{gcm: gcm}, nil
}

// Crypt encrypts the given message using AES-GCM with the provided additional data.
func (e *GCMEncryptorDecryptor) Crypt(message []byte, additionalData []byte) ([]byte, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := e.gcm.Seal(nonce, nonce, message, additionalData)
	return ciphertext, nil
}

// Crypt decrypts the given cipher package using AES-GCM.
func (d *GCMEncryptorDecryptor) Crypt2(cipherpackage []byte) ([]byte, []byte, error) {
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

// func decryptGCM(encryptionKey []byte, input []byte) string {
// 	block, err := aes.NewCipher(encryptionKey)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	aesgcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	nonce := input[:aesgcm.NonceSize()]
// 	ciphertext, err := aesgcm.Open(nil, nonce, input, nil)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	vault := make([]byte, len(ciphertext)+len(nonce))
// 	copy(vault, nonce)
// 	copy(vault[:len(nonce)], ciphertext)

// 	return string(vault)
// }

// func encryptGCM(encryptionKey []byte, input []byte) string {
// 	block, err := aes.NewCipher(encryptionKey)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	aesgcm, err := cipher.NewGCM(block)
// 	if err != nil {
// 		panic(err.Error())
// 	}
// 	nonce := make([]byte, aesgcm.NonceSize())
// 	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
// 		panic(err.Error())
// 	}
// 	ciphertext := aesgcm.Seal(nil, nonce, input, nil)

// 	return string(ciphertext)
// }
