package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/u8717/crypt/internal/persist"
)

type Manager struct {
	files persist.Ops
	crypt Crypt
}

func NewManger(location string) Manager {
	files, err := persist.NewFileOps(location)
	if err != nil {
		panic(err.Error())
	}
	return Manager{files: files, crypt: AESCrypt{}}
}

func (f Manager) Register(integrityToken, encryptionToken Secret, key Key) error {
	fileName := keyToDataPath(key)

	err := f.files.Create(fileName)
	if err != nil {
		return err
	}

	v, err := newVault(key, integrityToken, time.Now().UTC(), uuid.New().String())
	if err != nil {
		return err
	}

	jsonData, err := json.Marshal(v)
	if err != nil {
		return err
	}

	metadata := jsonData
	encrypted := encryptionToken != ""
	if encrypted {
		metadata, err = f.crypt.Encrypt(metadata, encryptionToken)
		if err != nil {
			return err
		}
	}

	err = f.files.Create(keyToMetaPath(key))
	if err != nil {
		return err
	}

	d := meta{
		Payload:   string(metadata),
		Encrypted: encrypted,
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	err = f.files.AppendTo(keyToMetaPath(key), b)
	if err != nil {
		return err
	}

	return nil
}

func (f Manager) Get(integrityToken, encryptionToken Secret, key Key) (vault, error) {
	readLastLine, err := f.files.ReadLast(keyToDataPath(key))
	if err != nil {
		return vault{}, err
	}
	if encryptionToken != "" {
		readLastLine, err = f.crypt.Decrypt(readLastLine, encryptionToken)
		if err != nil {
			return vault{}, err
		}
	}

	var v vault
	json.Unmarshal([]byte(readLastLine), &v)
	if v.TS == "" {
		return vault{}, fmt.Errorf("data in invalid state")
	}
	timestamp, err := parseTime(v.TS)
	if err != nil {
		return vault{}, err
	}
	should, err := newVault(key, integrityToken, *timestamp, v.Payload)
	if err != nil {
		return vault{}, err
	}
	if err := VerifySignature(should.Signature, v.Signature); err != nil {
		return vault{}, err
	}
	return v, nil
}

func (f Manager) Insert(integrityToken, encryptionToken Secret, timestamp time.Time, key Key, payload string) (string, string, error) {
	m, err := f.files.ReadWhole(keyToMetaPath(key))
	if err != nil {
		return "", "", err
	}
	var me meta
	err = json.Unmarshal(m, &me)
	if err != nil {
		return "", "", err
	}
	metaRec := []byte(me.Payload)
	if me.Encrypted && encryptionToken == "" {
		return "", "", fmt.Errorf("this key is not encrypted but was called without encrpytion key")
	}
	if !me.Encrypted && encryptionToken != "" {
		return "", "", fmt.Errorf("this key is not encrypted but was called with encrpytion key")
	}
	if me.Encrypted {
		metaRec, err = f.crypt.Decrypt(metaRec, encryptionToken)
		if err != nil {
			return "", "", err
		}
	}
	var metadataVault vault
	err = json.Unmarshal([]byte(metaRec), &metadataVault)
	if err != nil {
		return "", "", err
	}
	if _, err := uuid.Parse(metadataVault.Payload); err != nil {
		return "", "", err
	}
	t, err := parseTime(metadataVault.TS)
	if err != nil {
		return "", "", err
	}
	should, err := newVault(key, integrityToken, *t, metadataVault.Payload)
	if err != nil {
		return "", "", err
	}
	if err := VerifySignature(should.Signature, metadataVault.Signature); err != nil {
		return "", "", err
	}

	v, err := newVault(key, integrityToken, timestamp.UTC(), payload)
	if err != nil {
		return "", "", err
	}
	jsonData, err := json.Marshal(v)
	if err != nil {
		return "", "", err
	}

	compacted := new(bytes.Buffer)
	err = json.Compact(compacted, jsonData)
	if err != nil {
		return "", "", err
	}
	entry := compacted.Bytes()
	if me.Encrypted {
		entry, err = f.crypt.Encrypt(entry, encryptionToken)
		if err != nil {
			return "", "", err
		}
	}
	err = f.files.AppendTo(keyToDataPath(key), []byte(entry))
	if err != nil {
		return "", "", err
	}
	return v.Signature, string(entry), nil
}

func (f Manager) Delete(integrityToken, encryptionToken Secret, key Key) error {
	err := f.files.Delete(keyToDataPath(key))
	if err != nil {
		return err
	}
	err = f.files.Delete(keyToMetaPath(key))
	if err != nil {
		return err
	}
	return nil
}

func (f Manager) Import(integrityToken, encryptionToken Secret, recs ...record) []error {
	errs := make([]error, len(recs))
	for _, rec := range recs {
		fromStore, err := f.Get(integrityToken, encryptionToken, rec.Key)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		t1, err := parseTime(fromStore.TS)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		vFromStore, err := newVault(rec.Key, integrityToken, *t1, fromStore.Payload)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		err = VerifySignature(vFromStore.Signature, fromStore.Signature)
		if err != nil {
			errs = append(errs, err)
			continue
		}

		t2, err := parseTime(rec.Vault.TS)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if fromStore.TS == rec.Vault.TS && fromStore.Payload != rec.Vault.Payload {
			err := fmt.Errorf("timestamps match but values does not")
			errs = append(errs, err)
			continue
		}
		if t1.After(*t2) {
			err := fmt.Errorf("record is older")
			errs = append(errs, err)
			continue
		}

		_, _, err = f.Insert(integrityToken, "", *t2, rec.Key, rec.Vault.Payload) // encryptionToken left blank to omit reencrypting
		if err != nil {
			errs = append(errs, err)
			continue
		}
	}
	return errs
}

func (f Manager) Keys(namespace string, sortedResult bool, pageSize, pageNumber int) (Keys, error) {
	var keys Keys
	res, err := f.files.List()
	if err != nil {
		return nil, err
	}
	for _, k := range res {
		if strings.HasPrefix(k, DATAPREFIX+SEPARATENAMESPACE+namespace) && strings.HasSuffix(k, DATASUFIX) {
			s, ok := strings.CutSuffix(k, DATASUFIX)
			if !ok {
				return nil, fmt.Errorf("filepath structure is broken")
			}
			s, ok = strings.CutPrefix(s, DATAPREFIX+SEPARATENAMESPACE+namespace)
			if !ok {
				return nil, fmt.Errorf("filepath structure is broken")
			}
			parts := strings.SplitAfterN(s, SEPARATETYPE, 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("filepath structure is broken")
			}

			keys = append(keys, Key{
				Namespace:  namespace,
				Kind:       NewKind(parts[0]),
				Identifier: parts[1],
			})
		}
	}

	if sortedResult {
		sort.Sort(keys)
	}

	startIdx := pageSize * (pageNumber - 1)
	endIdx := startIdx + pageSize

	if startIdx < 0 {
		startIdx = 0
	}

	if endIdx > len(keys) || endIdx == 0 {
		endIdx = len(keys)
	}

	return keys[startIdx:endIdx], nil
}
