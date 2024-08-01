package store

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

const SPERATE = " ::: "
const RFC3339Nano = time.RFC3339Nano
const DATAPREFIX = "FILES_"
const DATASUFIX = ".filesdata"
const METAPREFIX = "FILES_"
const METASUFIX = ".filesmeta"
const SEPARATENAMESPACE = "$$$"
const SEPARATETYPE = "$$$$"

type Records interface {
	Register(integrityToken, encryptionToken Secret, key Key) error
	Get(integrityToken, encryptionToken Secret, key Key) (vault, error)
	Insert(integrityToken, encryptionToken Secret, timestamp time.Time, key Key, payload string) (string, string, error)
	Delete(integrityToken, encryptionToken Secret, key Key) error
	Import(integrityToken, encryptionToken Secret, recs ...record) []error
	Keys(namespace string, sort bool, pageSize, pageNumber int) (Keys, error)
}

func Serialize(rec record, signingToken Secret) (string, error) {
	timestamp, err := time.Parse(RFC3339Nano, rec.Vault.TS)
	if err != nil {
		return "", fmt.Errorf("failed to parse timestamp: %v", err)
	}

	serialized := fmt.Sprintf("%s%s%s%s%s%s%s%s%s%s%s",
		rec.Vault.Signature, SPERATE, timestamp.UTC().Format(RFC3339Nano), SPERATE,
		rec.Key.Namespace, SPERATE, rec.Key.Kind.String(), SPERATE, rec.Key.Identifier, SPERATE, rec.Vault.Payload,
	)

	return serialized, nil
}

func Deserialize(integrityToken Secret, inputs ...string) ([]record, error) {
	records := make([]record, 0, len(inputs))
	for _, input := range inputs {
		parts := strings.SplitN(input, SPERATE, 6)
		if len(parts) != 6 {
			return nil, fmt.Errorf("invalid input format: expected 6 parts, got %d", len(parts))
		}

		signature, ts, namespace, kind, id, payload := parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]

		k, err := NewKeyFromString(namespace, id, NewKind(kind))
		if err != nil {
			return nil, fmt.Errorf("failed to create ID: %v", err)
		}

		timestamp, err := time.Parse(RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("failed to parse timestamp: %v", err)
		}

		v, err := newVault(k, integrityToken, timestamp, payload)
		if err != nil {
			return nil, fmt.Errorf("failed to create signed record: %v", err)
		}

		err = VerifySignature(v.Signature, signature)
		if err != nil {
			return nil, fmt.Errorf("failed to verify signature: %v", err)
		}
		records = append(records, record{
			Key:   k,
			Vault: v,
		})
	}
	return records, nil
}

func NewRecord(key Key, integrityToken Secret, timestamp time.Time, payload string) (record, error) {
	toSign := fmt.Sprintf("%s, %s, %s, %s", key.Namespace, key.Identifier, timestamp.UTC().Format(RFC3339Nano), payload)
	signature := GenerateHMAC([]byte(toSign), []byte(integrityToken), sha256.New)
	v := vault{
		TS:        timestamp.UTC().Format(RFC3339Nano),
		Payload:   payload,
		Signature: string(signature),
	}
	return record{Key: key, Vault: v}, nil
}

type vault struct {
	TS        string `json:"ts"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type meta struct {
	Payload   string `json:"entry"`
	Encrypted bool   `json:"encrypted"`
}

type record struct {
	Key   Key `json:"key"`
	Vault vault
}

func newVault(key Key, integrityToken Secret, timestamp time.Time, payload string) (vault, error) {
	toSign := fmt.Sprintf("%s, %s, %s, %s", key.Namespace, key.Identifier, timestamp.UTC().Format(RFC3339Nano), payload)
	signature := GenerateHMAC([]byte(toSign), []byte(integrityToken), sha256.New)

	return vault{
		TS:        timestamp.UTC().Format(RFC3339Nano),
		Payload:   payload,
		Signature: string(signature),
	}, nil
}

func keyToDataPath(key Key) string {
	fileName := fmt.Sprintf("%v%v%v%v%v%v", DATAPREFIX, SEPARATENAMESPACE, key.Namespace, SEPARATETYPE, key.Identifier, DATASUFIX)
	return fileName
}

func keyToMetaPath(key Key) string {
	fileName := fmt.Sprintf("%v%v%v%v%v%v", METAPREFIX, SEPARATENAMESPACE, key.Namespace, SEPARATETYPE, key.Identifier, METASUFIX)
	return fileName
}
