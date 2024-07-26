package store_test

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/u8717/crypt/store"
)

func TestRecordsStore(t *testing.T) {
	name := uuid.New().String()
	key, err := store.NewKey("", name)
	if err != nil {
		t.Errorf("store was not created %s", err)
	}
	var encryption store.Secret = "0123456789123456"
	var integrityToken store.Secret = "my        secret"
	var fileStore store.Records = store.NewManger()

	err = fileStore.Register(integrityToken, encryption, key)
	if err != nil {
		t.Errorf("store was not created %s", err)
	}
	defer fileStore.Delete(integrityToken, encryption, key)

	_, err = fileStore.Get(integrityToken, encryption, key)
	if err == nil {
		t.Errorf("reading an empty file should result in an error")
	}

	ts := time.Now().UTC()
	value := "new value"
	//TODO:
	_, _, err = fileStore.Insert(integrityToken, encryption, ts, key, value)
	if err != nil {
		t.Errorf("error appending entry: %s", err)
	}

	rec, err := fileStore.Get(integrityToken, encryption, key)
	if err != nil {
		t.Errorf("error getting entry: %s", err)
	}

	if rec.Signature == "" || rec.TS == "" || rec.Payload != value {
		t.Errorf("unexpected values retrieved after appending entry")
	}

	err = fileStore.Delete(integrityToken, encryption, key)
	if err != nil {
		t.Errorf("error deleting entry: %s", err)
	}

	_, err = fileStore.Get(integrityToken, encryption, key)
	if err == nil {
		t.Errorf("getting a deleted entry should result in an error")
	}
}

func TestKeys(t *testing.T) {
	t.Run("EmptyDirectory", func(t *testing.T) {
		f := store.NewManger()
		result, err := f.Keys("namespace1", "a", true, 10, 1)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		expected := store.Keys{} // Empty slice for an empty directory
		if len(result) != len(expected) {
			t.Errorf("Unexpected result. Expected %v, got %v", expected, result)
		}
	})

	t.Run("NonEmptyDirectory", func(t *testing.T) {
		f := store.NewManger()

		var encryption store.Secret = "0123456789123456"
		var integrityToken store.Secret = "my        secret"
		id1 := store.Key{Kind: 0, Namespace: "test", Identifier: uuid.New().String()}
		err := f.Register(integrityToken, encryption, id1)
		if err != nil {
			t.Fatalf("Error creating test entry: %v", err)
		}
		defer f.Delete(integrityToken, encryption, id1)
		id2 := store.Key{Kind: 0, Namespace: "test", Identifier: uuid.New().String()}
		err = f.Register(integrityToken, encryption, id2)
		if err != nil {
			t.Fatalf("Error creating test entry: %v", err)
		}
		defer f.Delete(integrityToken, encryption, id2)

		dir, err := os.Getwd()
		if err != nil {
			slog.Error("Listing keys", "error", err)
			return
		}
		result, err := f.Keys("test", dir, true, 10, 1)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		expectedCount := 2
		if len(result) != expectedCount {
			t.Errorf("Unexpected result count. Expected %d, got %d", expectedCount, len(result))
		}
	})
}

func TestMerge(t *testing.T) {
	f := store.NewManger()

	namespace := "namespace1"
	key := store.Key{Namespace: namespace, Kind: store.String, Identifier: "test_key"}
	var encryptionToken store.Secret = ""
	var integrityToken store.Secret = "my        secret"
	err := f.Register(integrityToken, encryptionToken, key)
	if err != nil {
		t.Fatalf("Error creating test entry: %v", err)
	}
	defer f.Delete(integrityToken, encryptionToken, key)
	_, _, err = f.Insert(integrityToken, encryptionToken, time.Now().UTC(), key, "initial_value")
	if err != nil {
		t.Fatalf("Error inserting initial record: %v", err)
	}

	rec, err := store.NewRecord(key, integrityToken, time.Now().UTC().Add(time.Hour), "test text")
	if err != nil {
		t.Fatalf("Error inserting initial record: %v", err)
	}

	errs := f.Import(integrityToken, encryptionToken, rec)
	for _, err2 := range errs {
		if err2 != nil {
			t.Error("Merging item", "error", err2)
		}
	}
}

func TestSerializationDeserialization(t *testing.T) {
	var integrityToken store.Secret = "my        secret"

	namespace := "namespace1"
	key := "test_key"
	kind := store.String
	id, err := store.NewKeyFromString(namespace, key, kind)
	if err != nil {
		t.Fatalf("Error creating ID: %v", err)
	}

	timestamp := time.Now().UTC()
	payload := "test_payload"
	r, err := store.NewRecord(id, integrityToken, timestamp, payload)
	if err != nil {
		t.Fatalf("Error creating signed record: %v", err)
	}

	serialized, err := store.Serialize(r, integrityToken)
	if err != nil {
		t.Fatalf("Error serializing: %v", err)
	}

	recs, err := store.Deserialize(integrityToken, serialized)
	if err != nil {
		t.Fatalf("Error deserializing: %v", err)
	}
	if len(recs) != 1 {
		err := fmt.Errorf("expected one element")
		slog.Error("Merging item", "error", err)
		return
	}
	rec := recs[0]
	if rec.Key.Identifier != key {
		t.Errorf("Expected key %s, got %s", key, rec.Key.Identifier)
	}

}
