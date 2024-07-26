package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/u8717/crypt/persist"
)

type Manager struct {
	files persist.Ops
	crypt Crypt
}

func NewManger() Manager {
	return Manager{files: persist.File{}, crypt: AESCrypt{}}
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

	metadata := string(jsonData)
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
		Payload:   metadata,
		Encrypted: encrypted,
	}
	b, err := json.Marshal(d)
	if err != nil {
		return err
	}

	err = f.files.AppendToFile(keyToMetaPath(key), string(b))
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
	metaRec := me.Payload
	if me.Encrypted && encryptionToken == "" {
		return "", "", fmt.Errorf("this key is not encrypted but was called without encrpytion key")
	}
	if !me.Encrypted && encryptionToken != "" {
		return "", "", fmt.Errorf("this key is not encrypted but was called with encrpytion key")
	}
	if me.Encrypted {
		metaRec, err = f.crypt.Decrypt(me.Payload, encryptionToken)
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
	entry := compacted.String()
	if me.Encrypted {
		entry, err = f.crypt.Encrypt(entry, encryptionToken)
		if err != nil {
			return "", "", err
		}
	}
	err = f.files.AppendToFile(keyToDataPath(key), entry)
	if err != nil {
		return "", "", err
	}
	return v.Signature, entry, nil
}

func (f Manager) Delete(integrityToken, encryptionToken Secret, key Key) error {
	err := f.files.DeleteFile(keyToDataPath(key))
	if err != nil {
		return err
	}
	err = f.files.DeleteFile(keyToMetaPath(key))
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

func (f Manager) Keys(namespace, pwd string, sortedResult bool, pageSize, pageNumber int) (Keys, error) {
	dir := pwd
	var keys Keys
	err := f.files.WalkDir(dir, func(path string, de fs.DirEntry, err error) error {
		if de == nil {
			return nil
		}
		if strings.HasPrefix(de.Name(), DATAPREFIX+SEPARATENAMESPACE+namespace) && strings.HasSuffix(de.Name(), DATASUFIX) {
			s := filepath.Base(path)
			s, ok := strings.CutSuffix(s, DATASUFIX)
			if !ok {
				return fmt.Errorf("filepath structure is broken")
			}
			s, ok = strings.CutPrefix(s, DATAPREFIX+SEPARATENAMESPACE+namespace)
			if !ok {
				return fmt.Errorf("filepath structure is broken")
			}
			parts := strings.SplitAfterN(s, SEPARATETYPE, 2)
			if len(parts) != 2 {
				return fmt.Errorf("filepath structure is broken")
			}

			keys = append(keys, Key{
				Namespace:  namespace,
				Kind:       NewKind(parts[0]),
				Identifier: parts[1],
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
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

func parseTime(ts string) (*time.Time, error) {
	parsedTime, err := time.Parse(RFC3339Nano, ts)
	if err != nil {
		return nil, err
	}

	return &parsedTime, nil
}
