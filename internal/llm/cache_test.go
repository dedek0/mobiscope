package llm

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCacheKey_Deterministic(t *testing.T) {
	k1 := CacheKey("ollama", "qwen2.5:7b", "hello", 0.7)
	k2 := CacheKey("ollama", "qwen2.5:7b", "hello", 0.7)
	assert.Equal(t, k1, k2)
	assert.Len(t, k1, 32) // 16 bytes hex
}

func TestCacheKey_DifferentInputs(t *testing.T) {
	k1 := CacheKey("ollama", "model1", "prompt", 0)
	k2 := CacheKey("openai", "model1", "prompt", 0)
	assert.NotEqual(t, k1, k2)
}

func TestCache_SetAndGet(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)

	key := CacheKey("test", "model", "prompt", 0)
	value := json.RawMessage(`{"test":"response"}`)

	require.NoError(t, cache.Set(key, value))

	raw := cache.Get(key)
	require.NotNil(t, raw)
	assert.Contains(t, string(*raw), "response")
}

func TestCache_SetRejectsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)

	err := cache.Set("k", json.RawMessage(`not json`))
	require.Error(t, err)

	err = cache.Set("k", json.RawMessage(``))
	require.Error(t, err)

	assert.Nil(t, cache.Get("k"))
}

func TestCache_Miss(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)

	raw := cache.Get("nonexistent")
	assert.Nil(t, raw)
}

func TestCache_Expiry(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Millisecond)

	key := CacheKey("test", "model", "prompt", 0)
	require.NoError(t, cache.Set(key, json.RawMessage(`"value"`)))

	time.Sleep(10 * time.Millisecond)

	raw := cache.Get(key)
	assert.Nil(t, raw)
}

func TestCache_Clear(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)

	require.NoError(t, cache.Set("k1", json.RawMessage(`"v1"`)))
	require.NoError(t, cache.Set("k2", json.RawMessage(`"v2"`)))

	require.NoError(t, cache.Clear())
	assert.Nil(t, cache.Get("k1"))
	assert.Nil(t, cache.Get("k2"))
}

func TestCache_ZeroTTL(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, 0) // no expiry

	key := CacheKey("test", "model", "prompt", 0)
	require.NoError(t, cache.Set(key, json.RawMessage(`"value"`)))

	raw := cache.Get(key)
	assert.NotNil(t, raw)
}

func TestCache_KeyPath(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)
	key := CacheKey("test", "model", "prompt", 0)
	assert.Contains(t, cache.KeyPath(key), dir)
	assert.Contains(t, cache.KeyPath(key), ".json")
}

// TestCache_ConcurrentGetSet exercises Get and Set from multiple goroutines;
// it is primarily meaningful under -race, where a TOCTOU in the cache would
// surface as a data race or a panic.
func TestCache_ConcurrentGetSet(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)

	keys := []string{
		CacheKey("p1", "m1", "prompt-a", 0),
		CacheKey("p2", "m2", "prompt-b", 0),
	}

	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				key := keys[w%len(keys)]
				value := json.RawMessage(fmt.Sprintf(`{"writer":%d,"iter":%d}`, w, i))
				if err := cache.Set(key, value); err != nil {
					t.Errorf("concurrent set: %v", err)
					return
				}
				_ = cache.Get(key)
			}
		}()
	}
	for r := 0; r < 8; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				for _, key := range keys {
					// Readers must tolerate a torn read (Set is not atomic)
					// but must never panic.
					if raw := cache.Get(key); raw != nil {
						_ = json.Valid(*raw)
					}
				}
			}
		}()
	}
	wg.Wait()

	// After all writers finish, every key must hold complete, valid JSON.
	for _, key := range keys {
		raw := cache.Get(key)
		require.NotNil(t, raw)
		assert.True(t, json.Valid(*raw), "final value must be valid JSON")
	}

	// A final Set/Get round-trip still works.
	key := keys[0]
	require.NoError(t, cache.Set(key, json.RawMessage(`{"final":true}`)))
	raw := cache.Get(key)
	require.NotNil(t, raw)
	assert.Equal(t, `{"final":true}`, string(*raw))
}

// TestCache_CorruptFileOnDisk writes garbage straight into the cache path and
// asserts Get never panics. Get's contract is to pass bytes through (callers
// validate with json.Valid); a stricter future Get returning nil (a miss) is
// equally acceptable here.
func TestCache_CorruptFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)
	key := CacheKey("test", "model", "prompt", 0)

	require.NoError(t, os.WriteFile(cache.KeyPath(key), []byte(`{"broken": `), 0o600))

	raw := cache.Get(key)
	if raw != nil {
		assert.False(t, json.Valid(*raw), "corrupt bytes must not be presented as valid JSON")
		var probe map[string]interface{}
		assert.Error(t, json.Unmarshal(*raw, &probe), "unmarshal of corrupt data must fail cleanly, not panic")
	}

	// A subsequent valid Set overwrites the corruption.
	require.NoError(t, cache.Set(key, json.RawMessage(`{"recovered":true}`)))
	raw = cache.Get(key)
	require.NotNil(t, raw)
	assert.True(t, json.Valid(*raw))
	assert.Contains(t, string(*raw), "recovered")
}

// TestCache_KeyPathIsDirectory covers the case where the cache path exists but
// is not a readable file: Get must treat it as a miss without panicking.
func TestCache_KeyPathIsDirectory(t *testing.T) {
	dir := t.TempDir()
	cache := NewCacheInDir(dir, time.Hour)
	key := CacheKey("test", "model", "prompt", 0)

	require.NoError(t, os.MkdirAll(cache.KeyPath(key), 0o755))
	assert.Nil(t, cache.Get(key))
}
