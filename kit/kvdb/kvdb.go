package kvdb

import (
	"encoding/gob"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"sync"
)

const (
	DefaultDB = "skt.db"
	Memory    = "memory"
	Disk      = "disk"
)

type DataBase struct {
	mode string
	sync.RWMutex
	m map[string]string
}

func newDB(mode string) *DataBase {
	return &DataBase{
		mode: mode,
		m:    map[string]string{},
	}
}

func InitDB(mode string) (*DataBase, error) {
	db := newDB(mode)

	switch mode {
	case Memory:
		return db, nil
	case Disk:
		if _, err := os.Stat(DefaultDB); os.IsNotExist(err) {
			err := db.Save()
			if err != nil {
				return nil, err
			}
		}
		err := db.Load()
		if err != nil {
			return nil, err
		}
		return db, nil
	default:
		return nil, errors.New("unknown database mode")
	}
}

func (db *DataBase) Load() error {
	f, err := os.Open(DefaultDB)
	if err != nil {
		return err
	}

	err = decodeGob(f, &db.m)
	if err != nil {
		return err
	}
	return nil
}

func (db *DataBase) Save() error {
	f, err := os.Create(DefaultDB)
	if err != nil {
		return err
	}
	defer f.Close()

	err = encodeGob(f, db.m)
	if err != nil {
		return err
	}
	return nil
}

func (db *DataBase) Get(key string) (string, bool) {
	db.RLock()
	defer db.RUnlock()

	value, ok := db.m[key]
	return value, ok
}

func (db *DataBase) Set(key, value string) error {
	db.Lock()
	defer db.Unlock()

	oldValue := db.m[key]
	db.m[key] = value

	// TODO refactor code repetition in Set and Delete functions,
	// maybe we need to implement 'transactions':
	// func (db *DataBase) (operation, payload) error {
	// 		db.Lock()
	// 		operation(payload)
	// 		if mode==disk { db.Save() }
	// 		revert operation if saving failed
	// 		db.Unlock()
	// }
	if db.mode == Disk {
		err := db.Save()
		if err != nil {
			// revert old value and return error
			db.m[key] = oldValue
			return err
		}
	}

	return nil
}

func (db *DataBase) Delete(key string) error {
	db.Lock()
	defer db.Unlock()

	oldValue := db.m[key]
	delete(db.m, key)

	if db.mode == Disk {
		err := db.Save()
		if err != nil {
			db.m[key] = oldValue
			return err
		}
	}

	return nil
}

func (db *DataBase) Keys(pattern string) ([]string, error) {
	db.RLock()
	defer db.RUnlock()

	var result []string
	for k := range db.m {
		m, err := globMatch(pattern, k)
		if err != nil {
			return nil, err
		}
		if m {
			result = append(result, k)
		}
	}
	return result, nil
}

func (db *DataBase) Dump() ([]byte, error) {
	return json.Marshal(db.m)
}

func encodeGob(r io.Writer, object interface{}) error {
	encoder := gob.NewEncoder(r)
	return encoder.Encode(object)
}

func decodeGob(r io.Reader, object interface{}) error {
	decoder := gob.NewDecoder(r)
	return decoder.Decode(object)
}

var globsRegex = regexp.MustCompile(`\*+`)

func globMatch(pattern string, s string) (bool, error) {
	p := globsRegex.ReplaceAllString(pattern, ".*")
	r, err := regexp.Compile("^" + p + "$")
	return r.MatchString(s), err
}
