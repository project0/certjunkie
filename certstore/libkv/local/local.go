package local

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
)

const LOCAL = "local"

// Local "libkv" store.
type Local struct {
	// Endpoints passed to InitializeMock
	Endpoints []string

	// Options passed to InitializeMock
	Options *store.Config
}

// Register registers local to libkv
func Register() {
	libkv.AddStore(LOCAL, New)
}

// New creates a local store
func New(addrs []string, options *store.Config) (store.Store, error) {
	return &Local{
		Options: options,
	}, nil
}

func (l *Local) absolutePath(relativePath string) string {
	return filepath.Clean(filepath.Join(l.Options.Bucket, relativePath))
}

func (l *Local) checkPath(relativePath string) error {
	path := relativePath
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return os.MkdirAll(path, 0700)
	}
	return nil
}

// Put value to file
func (l *Local) Put(key string, value []byte, opts *store.WriteOptions) error {
	path := l.absolutePath(key)
	// just create the dir
	if opts != nil && opts.IsDir {
		return l.checkPath(path)
	}

	// create dir first
	if err := l.checkPath(filepath.Dir(path)); err != nil {
		return err
	}
	return os.WriteFile(path, value, 0600)

}

// Get file content
func (l *Local) Get(key string) (*store.KVPair, error) {

	// If pair is nil then the key does not exist
	exists, err := l.Exists(key)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, store.ErrKeyNotFound
	}
	path := l.absolutePath(key)
	value, err := os.ReadFile(path)

	return &store.KVPair{Key: key, Value: value, LastIndex: 0}, err
}

// Delete file
func (l *Local) Delete(key string) error {
	if ok, _ := l.Exists(key); !ok {
		return store.ErrKeyNotFound
	}
	return os.Remove(l.absolutePath(key))
}

// Exists file
func (l *Local) Exists(key string) (bool, error) {
	info, err := os.Stat(l.absolutePath(key))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.IsDir() {
		return false, nil
	}

	return true, nil
}

// List files
func (l *Local) List(prefix string) ([]*store.KVPair, error) {
	var kv []*store.KVPair

	err := filepath.Walk(l.absolutePath(prefix), func(path string, info os.FileInfo, err error) error {
		if info == nil {
			return store.ErrKeyNotFound
		}
		if info.IsDir() {
			return nil
		}

		pair, getErr := l.Get(strings.TrimPrefix(path, l.Options.Bucket))
		if getErr == nil {
			kv = append(kv, pair)
		}

		return getErr
	})

	return kv, err
}

// Close is not required but needs to be implemented
func (l *Local) Close() {
}

// DeleteTree remove
func (l *Local) DeleteTree(prefix string) error {
	return os.RemoveAll(l.absolutePath(prefix))
}

// NewLock is not implemented
func (l *Local) NewLock(key string, options *store.LockOptions) (store.Locker, error) {
	return nil, store.ErrCallNotSupported
}

// Watch  is not implemented
func (l *Local) Watch(key string, stopCh <-chan struct{}) (<-chan *store.KVPair, error) {
	return nil, store.ErrCallNotSupported
}

// WatchTree  is not implemented
func (l *Local) WatchTree(prefix string, stopCh <-chan struct{}) (<-chan []*store.KVPair, error) {
	return nil, store.ErrCallNotSupported
}

// AtomicPut is not implemented
func (l *Local) AtomicPut(key string, value []byte, previous *store.KVPair, opts *store.WriteOptions) (bool, *store.KVPair, error) {
	return false, nil, store.ErrCallNotSupported
}

// AtomicDelete is not implemented
func (l *Local) AtomicDelete(key string, previous *store.KVPair) (bool, error) {
	return false, store.ErrCallNotSupported
}
