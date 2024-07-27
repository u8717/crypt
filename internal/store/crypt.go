package store

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
)

type Secret string

// TODO Replace with cipherlib
type Crypt interface {
	Encrypt(plaintext string, token Secret) (string, error)
	Decrypt(ciphertext string, token Secret) (string, error)
}

type AESCrypt struct{}

func VerifySignature(should, is string) error {
	// Constant-time comparison to mitigate timing attacks
	if subtle.ConstantTimeCompare([]byte(should), []byte(is)) != 1 {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func GenerateHMAC(message string, token []byte, g func() hash.Hash) string {
	h := hmac.New(g, token)
	h.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (AESCrypt) Encrypt(plaintext string, key Secret) (string, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// Pad the plaintext to a multiple of the block size
	paddedText := padPKCS7([]byte(plaintext), aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(paddedText))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// PKCS7 padding implementation
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func (AESCrypt) Decrypt(ciphertext string, token Secret) (string, error) {
	block, err := aes.NewCipher([]byte(token))
	if err != nil {
		return "", err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decodedCiphertext, decodedCiphertext)

	// Unpad the decrypted data
	plaintext, err := unpadPKCS7(decodedCiphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// unpadPKCS7 removes PKCS7 padding
func unpadPKCS7(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return nil, errors.New("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return nil, errors.New("invalid padding")
		}
	}

	return data[:len(data)-padding], nil
}
