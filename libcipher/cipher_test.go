package libcipher_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/u8717/crypt/libcipher"
)

func TestAESCBCHMAC_EncryptDecrypt(t *testing.T) {
	var testCases = []struct {
		name          string
		plaintext     []byte
		integrityKey  []byte
		encryptionKey []byte
		expectedError error
	}{
		{
			name:          "SuccessfulEncryptionDecryption",
			plaintext:     []byte("This is some super secret data to encrypt."),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
		},
		{
			name:          "EmptyPlaintext",
			plaintext:     []byte(""),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: nil,
		},
		{
			name:          "ShortEncryptionKey",
			plaintext:     []byte("Some data"),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("too_short"),
			expectedError: fmt.Errorf("encryption key too short"),
		},
		{
			name:          "ShortIntegrityKey",
			plaintext:     []byte("Some data"),
			integrityKey:  []byte("too_short"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: fmt.Errorf("integrity key too short"),
		},
		{
			name:          "SameKeys",
			plaintext:     []byte("Some data"),
			integrityKey:  []byte("mysecretencryptionkey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: fmt.Errorf("using same key for encryption and integrity is not allowed"),
		},
		{
			name:          "SameKeys",
			plaintext:     []byte("Some data"),
			integrityKey:  nil,
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: fmt.Errorf("integrity key too short"),
		},
		{
			name:          "SameKeys",
			plaintext:     []byte("Some data"),
			integrityKey:  []byte("mysecretencryptionkey12345671234"),
			encryptionKey: nil,
			expectedError: fmt.Errorf("encryption key too short"),
		},
		{
			name:          "SameKeys",
			plaintext:     nil,
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: fmt.Errorf("message was nil"),
		},
	}
	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cypher, err := testEncryptCBC(t, tc.encryptionKey, tc.integrityKey, tc.plaintext)
			if fmt.Sprint(err) != fmt.Sprint(tc.expectedError) {
				t.Fatalf(err.Error())
			}
			if tc.expectedError != nil {
				return
			}
			decryptedText, err := testDecryptCBC(t, tc.encryptionKey, tc.integrityKey, cypher)
			if fmt.Sprint(err) != fmt.Sprint(tc.expectedError) {
				t.Fatalf("%v : %v : %v", err.Error(), tc.expectedError, i)
			}
			if tc.expectedError != nil {
				return
			}
			if !bytes.Equal(decryptedText, tc.plaintext) {
				t.Fatal(fmt.Errorf("Decrypted data doesn't match original plaintext: %s : %s", decryptedText, tc.plaintext))
			}
		})
	}
}

func TestGCM_EncryptDecrypt(t *testing.T) {
	var testCases = []struct {
		name          string
		plaintext     []byte
		integrityKey  []byte
		encryptionKey []byte
		expectedError error
	}{
		{
			name:          "SuccessfulEncryptionDecryption",
			plaintext:     []byte("This is some super secret data to encrypt."),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
		},
		{
			name:          "EmptyPlaintext",
			plaintext:     []byte(""),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: nil,
		},
		{
			name:          "ShortEncryptionKey",
			plaintext:     []byte("Some data"),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("too_short"),
			expectedError: fmt.Errorf("encryption key too short"),
		},
		{
			name:          "SameKeys",
			plaintext:     []byte("Some data"),
			integrityKey:  []byte("mysecretencryptionkey12345671234"),
			encryptionKey: nil,
			expectedError: fmt.Errorf("encryption key too short"),
		},
		{
			name:          "SameKeys",
			plaintext:     nil,
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			expectedError: fmt.Errorf("message was nil"),
		},
	}
	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cypher, err := testEncryptGCM(t, tc.encryptionKey, tc.integrityKey, tc.plaintext)
			if fmt.Sprint(err) != fmt.Sprint(tc.expectedError) {
				t.Fatalf(err.Error())
			}
			if tc.expectedError != nil {
				return
			}
			decryptedText, err := testDecryptGCM(t, tc.encryptionKey, tc.integrityKey, cypher)
			if fmt.Sprint(err) != fmt.Sprint(tc.expectedError) {
				t.Fatalf("%v : %v : %v", err.Error(), tc.expectedError, i)
			}
			if tc.expectedError != nil {
				return
			}
			if !bytes.Equal(decryptedText, tc.plaintext) {
				t.Fatal(fmt.Errorf("Decrypted data doesn't match original plaintext: %s : %s", decryptedText, tc.plaintext))
			}
		})
	}
}

func TestAESCBCHMAC_Cyphertext(t *testing.T) {
	var testCases = []struct {
		name          string
		cypher        []byte
		plaintext     []byte
		integrityKey  []byte
		encryptionKey []byte
		expectedError error
	}{
		{
			name:          "SuccessfulEncryptionDecryption",
			cypher:        []byte("This is some super secret data to encrypt."),
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			plaintext:     []byte("This is some super secret data to encrypt."),
			expectedError: fmt.Errorf("cipherText is invalid"),
		},
		{
			name:          "SuccessfulEncryptionDecryption",
			cypher:        nil,
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			plaintext:     []byte("This is some super secret data to encrypt."),
			expectedError: fmt.Errorf("cipherText was nil"),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			decryptedText, err := testDecryptCBC(t, tc.encryptionKey, tc.integrityKey, tc.cypher)
			if fmt.Sprint(err) != fmt.Sprint(tc.expectedError) {
				t.Fatalf(err.Error())
			}
			if tc.expectedError != nil {
				return
			}
			if !bytes.Equal(decryptedText, tc.plaintext) {
				t.Fatal(fmt.Errorf("Decrypted data doesn't match original plaintext: %s : %s", decryptedText, tc.plaintext))
			}
		})
	}
}

func TestAESCBCHMAC_CyphertextIsRandomized(t *testing.T) {
	var testCases = []struct {
		name          string
		plaintext     []byte
		integrityKey  []byte
		encryptionKey []byte
		expectedError error
	}{
		{
			name:          "SuccessfulEncryptionDecryption",
			integrityKey:  []byte("anothersecretintegritykey12345671234"),
			encryptionKey: []byte("mysecretencryptionkey12345671234"),
			plaintext:     []byte("This is some super secret data to encrypt."),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cyphers := make([][]byte, 10)
			for i := range cyphers {
				cypher, err := testEncryptCBC(t, tc.encryptionKey, tc.integrityKey, tc.plaintext)
				if fmt.Sprint(err) != fmt.Sprint(tc.expectedError) {
					t.Fatalf(err.Error())
				}
				cyphers[i] = cypher
			}
			for i := range cyphers {
				for j := i + 1; j < len(cyphers); j++ {
					if bytes.Equal(cyphers[i], cyphers[j]) {
						t.Fatal("Not all cyphers are unique")
					}
				}
			}
		})
	}
}

func testEncryptCBC(t *testing.T, encryptionKey []byte, integrityKey []byte, plaintext []byte) ([]byte, error) {
	t.Helper()
	encrypter, err := libcipher.NewCBCHMACEncryptor(encryptionKey, integrityKey, sha256.New)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypter.Crypt(plaintext, nil)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext empty")
	}

	return ciphertext, nil
}

func testDecryptCBC(t *testing.T, encryptionKey []byte, integrityKey []byte, ciphertext []byte) ([]byte, error) {
	t.Helper()
	decrypter, err := libcipher.NewCBCHMACDecryptor(encryptionKey, integrityKey, sha256.New)
	if err != nil {
		return nil, err
	}
	decryptedText, _, err := decrypter.Crypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return decryptedText, nil
}

func testEncryptGCM(t *testing.T, encryptionKey []byte, _ []byte, plaintext []byte) ([]byte, error) {
	t.Helper()
	encrypter, err := libcipher.NewGCMEncryptor(encryptionKey, rand.Reader)
	if err != nil {
		return nil, err
	}

	ciphertext, err := encrypter.Crypt(plaintext, nil)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func testDecryptGCM(t *testing.T, encryptionKey []byte, _ []byte, ciphertext []byte) ([]byte, error) {
	t.Helper()
	decrypter, err := libcipher.NewGCMDecryptor(encryptionKey)
	if err != nil {
		return nil, err
	}
	decryptedText, _, err := decrypter.Crypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return decryptedText, nil
}
