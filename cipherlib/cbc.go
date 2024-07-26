package cipherlib

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
)

// Configure & init the AES-CBC+HMAC cryptor in encryption mode.
// AES-CBC with PKCS7 padding HMAC for integrity.
//
//	The final encrypted string format:
//	[ MAC | AD-Lenght | AD | Initialization Vector | Block 1 | Block 2 | ... ]
//	rand.Reader is used for introducing randomness.
//
// Don't use this for big messages, the whole cypher has to be in mem for computing the Hmac.
//
// The encryption key and integrity key must be distinct. Both keys have to be keept secret.
// Rotating must be done to both keys simultaneously.
//
// Compromised Encryption Key:
//
//	An attacker, possessing the encryption key, could decrypt sensitive data.
//	If you rotate only the integrity key, they still have access to the previously encrypted data.
//
// Compromised Integrity Key:
//
//	An attacker with the integrity key could potentially modify encrypted data,
//	forge HMACs, and tamper with the system without detection.
//	Even if you rotate the encryption key, the integrity of past data is compromised.
//
// the MAC is calculated from ( AD-Lenght | AD | Initialization Vector | Block 1 | Block 2 | ... )
//
// GCM Comparison:
//
//		Use CBC with HMAC over GCM (or any stream cipher) when avoiding nonce collisions can be challenging is a problem.
//		This is the case if you deal with:
//		- high-volume systems (the probability of nonce collisions increases, especially if the nonce space is limited).
//		- distributed environments (coordinating nonce generation across nodes and ensuring uniqueness becomes even more complex).
//		- or scenarios where encrypted data needs to be stored persistently. For example, if encrypted data is stored in a database.
//	      and later retrieved and re-encrypted, ensuring that a new, unique nonce is used each time can be challenging.
//
// Since this is a one-person project, ensure you review the code before using it to validate its security and correctness.
func NewCBCHMACEncryptor(encyptionKey []byte, integrityKey []byte, calculateMAC func() hash.Hash) (Encryptor, error) {
	cry, err := newCBCHMACryptor(encyptionKey, integrityKey, calculateMAC)
	if err != nil {
		return nil, err
	}
	return (encryptor)(cry), nil
}

// Configure & init the AES-CBC+HMAC cryptor in decryption mode.
func NewCBCHMACDecryptor(encyptionKey []byte, integrityKey []byte, calculateMAC func() hash.Hash) (Decryptor, error) {
	cry, err := newCBCHMACryptor(encyptionKey, integrityKey, calculateMAC)
	if err != nil {
		return nil, err
	}
	return (decryptor)(cry), nil
}

// Cncryption mode of the cryptor.
type encryptor cryptor

func (crytor encryptor) Crypt(message []byte, additionalData []byte) ([]byte, error) {
	if message == nil {
		return nil, fmt.Errorf("message was nil")
	}
	// Apply PKCS#7 padding to the input data.
	pad := padPKCS7(len(message), crytor.pher.BlockSize())
	payload := make([]byte, len(message)+len(pad))
	// Prepare the message by concatenating the input and padding.
	copy(payload[:len(message)], message)
	copy(payload[len(message):], pad)
	// Generate a random initialization vector (IV).
	iv := make([]byte, crytor.pher.BlockSize())
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	return crytor.seal(iv, payload, additionalData), nil
}

func (crytor encryptor) seal(iv []byte, plaintext []byte, additionalData []byte) []byte {
	// Calculate the total size needed for HMAC, additionalData header, additionalData, IV, encrypted data.
	cypherLen := len(plaintext) + crytor.pher.BlockSize() + crytor.macLenght + additionalDataHeaderLenght + len(additionalData)
	// Contruct slice to hold the encrypted text & Encrypt.
	cypherParcel := make([]byte, cypherLen)
	// Calculate AD length
	adLength := uint16(len(additionalData))
	// Encode AD length into bytes & copy it into the parcel.
	adHeaderLocation := crytor.macLenght
	adLocation := adHeaderLocation + additionalDataHeaderLenght
	binary.BigEndian.PutUint16(cypherParcel[adHeaderLocation:adLocation], adLength)
	ivLocation := adLocation + len(additionalData)
	copy(cypherParcel[adLocation:ivLocation], additionalData)
	// Store the IV after HMAC to the destination buffer.
	cipherTextLocation := ivLocation + len(iv)
	copy(cypherParcel[ivLocation:cipherTextLocation], iv)
	// Create a CBC decrypter and encrypt the message.
	mode := cipher.NewCBCEncrypter(crytor.pher, iv)
	mode.CryptBlocks(cypherParcel[cipherTextLocation:], plaintext)
	// Calculate the HMAC signature.
	hmac := generateSignature(crytor.integrityKey, crytor.calcMac, cypherParcel[adHeaderLocation:]...)
	// Store the HMAC at the beginning of destination buffer.
	copy(cypherParcel[:adHeaderLocation], hmac)

	return cypherParcel
}

// Decryption mode of the cryptor.
type decryptor cryptor

func (cryptor decryptor) Crypt(ciphertext []byte) ([]byte, []byte, error) {
	if ciphertext == nil {
		return nil, nil, fmt.Errorf("cipherText was nil")
	}
	if len(ciphertext) < cryptor.macLenght+cryptor.pher.BlockSize() {
		return nil, nil, fmt.Errorf("cipherText is invalid")
	}
	minCiphertextSize := cryptor.macLenght + additionalDataHeaderLenght + cryptor.pher.BlockSize()
	if len(ciphertext) < minCiphertextSize {
		return nil, nil, fmt.Errorf("cipherText is too short")
	}
	// Extract the HMAC from the beginning of the encrypted data.
	adHeaderLocation := cryptor.macLenght
	mac := ciphertext[:adHeaderLocation]
	err := verify(mac, cryptor.integrityKey, cryptor.calcMac, generateSignature, ciphertext[adHeaderLocation:]...)
	if err != nil {
		return nil, nil, fmt.Errorf("data integrity compromised %w", err)
	}
	// Extract additionalData lenght.
	adLocation := adHeaderLocation + additionalDataHeaderLenght
	adLengthHeader := ciphertext[adHeaderLocation:adLocation]
	adLength := binary.BigEndian.Uint16(adLengthHeader)
	// Exctract the additional data.
	ivLocation := adLocation + int(adLength)
	additionalData := ciphertext[adLocation:ivLocation]
	// Extract iv.
	cipherTextLocation := ivLocation + cryptor.pher.BlockSize()
	iv := ciphertext[ivLocation:cipherTextLocation]
	payload := ciphertext[cipherTextLocation:]

	// Init slice to hold the plaintext & decrypt.
	dst := make([]byte, len(payload))
	// Create a CBC decrypter and decrypt the message.
	mode := cipher.NewCBCDecrypter(cryptor.pher, iv)
	mode.CryptBlocks(dst, payload)
	// Calculate the padding index.
	unpadIndex, err := unpadPKCS7(dst)
	if err != nil {
		return nil, nil, err
	}
	message := make([]byte, unpadIndex)
	// Remove padding & return.
	copy(message, dst[:unpadIndex])

	return message, additionalData, nil
}

type cryptor struct {
	pher         cipher.Block
	macLenght    int
	calcMac      func() hash.Hash
	integrityKey []byte
}

// Configure & init the AES-CBC+HMAC Cryptor in encryption mode.
func newCBCHMACryptor(encyptionKey []byte, integrityKey []byte, calculateMAC func() hash.Hash) (cryptor, error) {
	const minKeySize = 16 // Replace with the desired minimum key size

	// Check key sizes.
	if len(encyptionKey) < minKeySize {
		return cryptor{}, fmt.Errorf("encryption key too short")
	}
	if len(integrityKey) < minKeySize {
		return cryptor{}, fmt.Errorf("integrity key too short")
	}

	// Check if the encryption key and integrity key are the same.
	if bytes.Equal(encyptionKey, integrityKey) {
		return cryptor{}, fmt.Errorf("using same key for encryption and integrity is not allowed")
	}
	block, err := aes.NewCipher(encyptionKey)
	if err != nil {
		return cryptor{}, err
	}

	newintegrityKey := make([]byte, len(integrityKey))
	copy(newintegrityKey, integrityKey)
	return cryptor{
		pher:         block,
		macLenght:    calculateMAC().Size(),
		integrityKey: newintegrityKey,
		calcMac:      calculateMAC,
	}, nil
}

// unpadPKCS7 returns the index of the PKCS7 padding start.
func unpadPKCS7(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, errors.New("empty input")
	}

	padding := int(data[len(data)-1])
	if padding > len(data) || padding == 0 {
		return 0, errors.New("invalid padding")
	}

	for i := len(data) - padding; i < len(data); i++ {
		if int(data[i]) != padding {
			return 0, errors.New("invalid padding")
		}
	}

	return len(data) - padding, nil
}

// padPKCS7 pads the data to a multiple of blockSize using PKCS7 padding.
func padPKCS7(dataLen int, blockSize int) []byte {
	padding := blockSize - (dataLen % blockSize)
	padText := bytes.Repeat([]byte{byte(padding)}, padding)

	return padText
}

// generateSignature generates HMAC for the message using the given token.
func generateSignature(token []byte, hashing func() hash.Hash, message ...byte) []byte {
	h := hmac.New(hashing, token)
	h.Write(message)

	return h.Sum(nil)
}

// verify verifies the integrity of the message using HMAC.
func verify(hmac, token []byte, hashing func() hash.Hash, should func(token []byte, hashing func() hash.Hash, message ...byte) []byte, message ...byte) error {
	// Constant-time comparison to mitigate timing attacks.
	if subtle.ConstantTimeCompare(should(token, hashing, message...), hmac) != 1 {
		return fmt.Errorf("signature verification failed")
	}

	return nil
}

const additionalDataHeaderLenght = 2
