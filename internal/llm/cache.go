package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/dedek0/mobiscope/internal/metrics"
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
		metrics.RecordCacheLookup(false)
		return nil
	}

	if c.ttl > 0 && time.Since(info.ModTime()) > c.ttl {
		os.Remove(path)
		metrics.RecordCacheLookup(false)
		return nil
	}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		metrics.RecordCacheLookup(false)
		return nil
	}
	if len(data) == 0 || !json.Valid(data) {
		// Corrupt entry: treat as a miss so callers recompute.
		metrics.RecordCacheLookup(false)
		return nil
	}

	raw := json.RawMessage(data)
	metrics.RecordCacheLookup(true)
	return &raw
}

// Set stores a raw JSON response in the cache. The value must be valid JSON;
// non-JSON payloads are rejected so callers cannot poison the cache. The
// write is atomic (temp file + rename) so concurrent Get callers never see a
// truncated file.
func (c *Cache) Set(key string, value json.RawMessage) error {
	if len(value) == 0 || !json.Valid(value) {
		return fmt.Errorf("cache value is not valid JSON")
	}
	path := filepath.Join(c.dir, key+".json")
	tmp, err := os.CreateTemp(c.dir, key+".tmp-*")
	if err != nil {
		return fmt.Errorf("creating cache temp file: %w", err)
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(value)
	if cerr := tmp.Close(); cerr != nil && werr == nil {
		werr = cerr
	}
	if werr != nil {
		os.Remove(tmpName)
		return fmt.Errorf("writing cache entry: %w", werr)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("committing cache entry: %w", err)
	}
	return nil
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

// KeyPath returns the filesystem path for a cache key (for testing).
func (c *Cache) KeyPath(key string) string {
	return filepath.Join(c.dir, key+".json")
}
