package local

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/docker/libkv"
	"github.com/docker/libkv/store"
	"github.com/docker/libkv/testutils"
	"github.com/stretchr/testify/assert"
)

func makeStore(t *testing.T, tmpdir string) store.Store {

	kv, err := New(
		[]string{},
		&store.Config{
			Bucket: tmpdir,
		},
	)

	if err != nil {
		t.Fatalf("cannot create store: %v", err)
	}

	assert.NotNil(t, kv)

	return kv
}

func TestRegister(t *testing.T) {
	Register()

	kv, err := libkv.NewStore(LOCAL, []string{}, nil)
	assert.NoError(t, err)
	assert.NotNil(t, kv)

	if _, ok := kv.(*Local); !ok {
		t.Fatal("Error registering and initializing local")
	}
}

func TestLocalStore(t *testing.T) {
	tmpdir, err := ioutil.TempDir("", "kvlocaltest")

	if err != nil {
		t.Fatalf("cannot create temp dir: %v", err)
	}

	kv := makeStore(t, tmpdir)
	//lockKV := makeStore(t)
	testutils.RunTestCommon(t, kv)
	//testutils.RunTestAtomic(t, kv)
	//testutils.RunTestWatch(t, kv)
	//testutils.RunTestLock(t, kv)
	//testutils.RunTestLockTTL(t, kv, lockKV)
	//testutils.RunTestTTL(t, kv, ttlKV)
	testutils.RunCleanup(t, kv)

	os.RemoveAll(tmpdir)
}
