package llm

import (
	"encoding/json"
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
