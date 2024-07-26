package store

import (
	"fmt"
	"strconv"
	"time"
)

type Key struct {
	Kind       kind
	Namespace  string
	Identifier interface{}
}

type kind int

const (
	None      kind = iota
	String    kind = iota
	Integer   kind = iota
	Timestamp kind = iota
)

func NewKey(namespace string, key string) (Key, error) {
	k := Key{
		Namespace:  namespace,
		Identifier: key,
	}

	switch k.Identifier.(type) {
	case string:
		k.Kind = String
	case int:
		k.Kind = Integer
	case time.Time:
		k.Kind = Timestamp
	default:
		return Key{}, fmt.Errorf("unsupported type for 'key'")
	}

	return k, nil
}

func NewKeyFromString(namespace string, key string, k kind) (Key, error) {

	switch k {
	case None:
		return Key{
			Namespace:  namespace,
			Kind:       k,
			Identifier: key,
		}, nil
	case String:
		return Key{
			Namespace:  namespace,
			Kind:       k,
			Identifier: key,
		}, nil
	case Integer:
		res, err := strconv.Atoi(key)
		if err != nil {
			return Key{}, err
		}
		return Key{
			Namespace:  namespace,
			Kind:       k,
			Identifier: res,
		}, nil
	case Timestamp:
		res, err := parseTime(key)
		if err != nil {
			return Key{}, err
		}
		return Key{
			Namespace:  namespace,
			Kind:       k,
			Identifier: *res,
		}, nil
	}
	return Key{}, fmt.Errorf("unsupported type for 'key'")
}

func (d kind) String() string {
	return [...]string{"None", "String", "Integer", "Timestamp"}[d]
}

func NewKind(s string) kind {
	switch s {
	case "None":
		return 0
	case "String":
		return 1
	case "Integer":
		return 2
	case "Timestamp":
		return 3
	}
	return 0
}

func (k Key) String() string {
	return fmt.Sprintf("%v%v%v%v%v", k.Namespace, SEPARATENAMESPACE, k.Kind, SEPARATENAMESPACE, k.Identifier)
}

type Keys []Key

func (s Keys) Len() int {
	return len(s)
}

func (s Keys) Less(i, j int) bool {
	// Customize the comparison logic here based on your sorting requirements
	// In this example, we are comparing based on Namespace and then Key
	if s[i].Namespace != s[j].Namespace {
		return s[i].Namespace < s[j].Namespace
	}

	switch s[i].Kind {
	case String:
		return s[i].Identifier.(string) < s[j].Identifier.(string)
	case Integer:
		return s[i].Identifier.(int) < s[j].Identifier.(int)
	case Timestamp:
		return s[i].Identifier.(time.Time).Before(s[j].Identifier.(time.Time))
	default:
		return false
	}
}

func (s Keys) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
