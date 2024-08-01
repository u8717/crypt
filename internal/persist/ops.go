package persist

// Ops defines the interface for file operations.
type Ops interface {
	// Create creates a new key.
	// It returns an error if the key already exists or if there is an issue creating the key.
	Create(key string) error
	// ReadWhole reads the entire content of the given key.
	// It returns the content as a byte slice or an error if the content cannot be read.
	ReadWhole(key string) ([]byte, error)
	// ReadLast reads the last entry of the given key.
	// It returns the last entry or an error if the file cannot be read.
	ReadLast(key string) ([]byte, error)
	// AppendTo appends an entry to the file with the given key.
	// It returns an error if the file cannot be opened or written to.
	AppendTo(key string, entry []byte) error
	// Delete deletes the given key and associated content.
	// It returns an error if the key or associated content cannot be deleted.
	Delete(key string) error
	// List lists all keys in the bucket-scope.
	// It returns a slice of key names or an error if the bucket-scope cannot be read.
	List() ([]string, error)
}

type (
	LocationError    string
	KeyError         string
	EntryError       string
	OpsInternalError string
)

func (e LocationError) Error() string {
	return "storelib/ops: " + (string)(e)
}
func (e KeyError) Error() string {
	return "storelib/ops: " + (string)(e)
}
func (e EntryError) Error() string {
	return "storelib/ops: " + (string)(e)
}
func (e OpsInternalError) Error() string {
	return "storelib/ops: " + (string)(e)
}
