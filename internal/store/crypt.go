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
	Encrypt(plaintext []byte, token Secret) ([]byte, error)
	Decrypt(ciphertext []byte, token Secret) ([]byte, error)
}

type AESCrypt struct{}

func VerifySignature(should, is string) error {
	// Constant-time comparison to mitigate timing attacks
	if subtle.ConstantTimeCompare([]byte(should), []byte(is)) != 1 {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

func GenerateHMAC(message []byte, token []byte, g func() hash.Hash) []byte {
	h := hmac.New(g, token)
	h.Write(message)
	return []byte(base64.StdEncoding.EncodeToString(h.Sum(nil)))
}

func (AESCrypt) Encrypt(plaintext []byte, key Secret) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}

	// Pad the plaintext to a multiple of the block size
	paddedText := padPKCS7([]byte(plaintext), aes.BlockSize)

	ciphertext := make([]byte, aes.BlockSize+len(paddedText))
	iv := ciphertext[:aes.BlockSize]

	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], paddedText)

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

// PKCS7 padding implementation
func padPKCS7(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func (AESCrypt) Decrypt(ciphertext []byte, token Secret) ([]byte, error) {
	block, err := aes.NewCipher([]byte(token))
	if err != nil {
		return nil, err
	}

	decodedCiphertext, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}

	iv := decodedCiphertext[:aes.BlockSize]
	decodedCiphertext = decodedCiphertext[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(decodedCiphertext, decodedCiphertext)

	// Unpad the decrypted data
	plaintext, err := unpadPKCS7(decodedCiphertext)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
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
