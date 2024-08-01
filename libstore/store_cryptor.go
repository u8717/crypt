package libstore

import (
	"fmt"
	"hash"
	"time"

	"github.com/u8717/crypt/libcipher"
)

const tsFormat = "2006-01-02 15:04:05.999999999 -0700 MST"

type CryptStore struct {
	storeOps  Ops
	encryptor libcipher.Encryptor
	decryptor libcipher.Decryptor
}

func NewManager(ops Ops, encyptionKey []byte, integrityKey []byte, calculateMAC func() hash.Hash) (Ops, error) {
	encryptor, err := libcipher.NewCBCHMACEncryptor(encyptionKey, integrityKey, calculateMAC)
	if err != nil {
		return nil, err
	}
	decryptor, err := libcipher.NewCBCHMACDecryptor(encyptionKey, integrityKey, calculateMAC)
	if err != nil {
		return nil, err
	}
	return CryptStore{storeOps: ops, encryptor: encryptor, decryptor: decryptor}, nil
}

// AppendTo implements libstore.Ops.
func (m CryptStore) AppendTo(key string, entry []byte) error {
	ts := []byte(time.Now().UTC().Format(tsFormat))
	vault, err := m.encryptor.Crypt(entry, ts)
	if err != nil {
		return err
	}
	err = m.storeOps.AppendTo(key, vault)
	if err != nil {
		return err
	}

	return nil
}

// Create implements libstore.Ops.
func (m CryptStore) Create(key string) error {
	err := m.storeOps.Create(key)
	if err != nil {
		return err
	}

	return nil
}

// Delete implements libstore.Ops.
func (m CryptStore) Delete(key string) error {
	err := m.storeOps.Delete(key)
	if err != nil {
		return err
	}

	return nil
}

// List implements libstore.Ops.
func (m CryptStore) List() ([]string, error) {
	res, err := m.storeOps.List()
	if err != nil {
		return nil, err
	}

	return res, nil
}

// ReadLast implements libstore.Ops.
func (m CryptStore) ReadLast(key string) ([]byte, error) {
	vault, err := m.storeOps.ReadLast(key)
	if err != nil {
		return nil, err
	}
	res, meta, err := m.decryptor.Crypt(vault)
	if err != nil {
		return nil, err
	}
	ts, err := time.Parse(tsFormat, string(meta))
	if err != nil {
		return nil, err
	}
	if ts.After(time.Now().UTC()) {
		return nil, fmt.Errorf("failed to validate sealing")
	}
	return res, nil
}

// ReadWhole implements libstore.Ops.
func (m CryptStore) ReadWhole(key string) ([][]byte, error) {
	vaults, err := m.storeOps.ReadWhole(key)
	if err != nil {
		return nil, err
	}
	res := make([][]byte, len(vaults))
	var meta []byte
	for i := range vaults {
		res[i], meta, err = m.decryptor.Crypt(vaults[i])
		if err != nil {
			return nil, err
		}
		ts, err := time.Parse(tsFormat, string(meta))
		if err != nil {
			return nil, err
		}
		if ts.After(time.Now().UTC()) {
			return nil, fmt.Errorf("failed to validate sealing")
		}
	}
	return res, nil
}
