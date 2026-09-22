package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Cache provides a file-based cache for LLM responses.
type Cache struct {
	dir string
	ttl time.Duration
}

// NewCache creates a cache in ~/.cache/mobiscope/llm/.
func NewCache(ttl time.Duration) (*Cache, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("getting home dir: %w", err)
	}
	dir := filepath.Join(home, ".cache", "mobiscope", "llm")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating cache dir: %w", err)
	}
	return &Cache{dir: dir, ttl: ttl}, nil
}

// NewCacheInDir creates a cache in a specific directory (for tests).
func NewCacheInDir(dir string, ttl time.Duration) *Cache {
	return &Cache{dir: dir, ttl: ttl}
}

// CacheKey computes the SHA256 cache key from provider, model, prompt, and temperature.
func CacheKey(provider, model, prompt string, temperature float64) string {
	input := fmt.Sprintf("%s|%s|%.4f|%s", provider, model, temperature, prompt)
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:16])
}

// Get retrieves a cached response. Returns nil if not found or expired.
func (c *Cache) Get(key string) *json.RawMessage {
	path := filepath.Join(c.dir, key+".json")
	info, err := os.Stat(path)
	if err != nil {
		return nil
	}

	if c.ttl > 0 && time.Since(info.ModTime()) > c.ttl {
		os.Remove(path)
		return nil
	}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		return nil
	}

	raw := json.RawMessage(data)
	return &raw
}

// Set stores a response in the cache.
func (c *Cache) Set(key string, value interface{}) error {
	data, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("marshaling cache value: %w", err)
	}
	path := filepath.Join(c.dir, key+".json")
	return os.WriteFile(path, data, 0o600)
}

// Clear removes all cached entries.
func (c *Cache) Clear() error {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		os.Remove(filepath.Join(c.dir, e.Name()))
	}
	return nil
}

// Stats returns cache hit/miss statistics.
type CacheStats struct {
	Hits   int
	Misses int
}

// KeyPath returns the filesystem path for a cache key (for testing).
func (c *Cache) KeyPath(key string) string {
	return filepath.Join(c.dir, key+".json")
}
