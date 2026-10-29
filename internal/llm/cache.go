package llm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
//
// The fields are length-prefixed before hashing: a plain "|" join made
// ("a|b", "c") and ("a", "b|c") collide, so a cached answer could be served
// for a different provider or model.
func CacheKey(provider, model, prompt string, temperature float64) string {
	var b strings.Builder
	for _, field := range []string{provider, model, fmt.Sprintf("%.4f", temperature), prompt} {
		fmt.Fprintf(&b, "%d:%s|", len(field), field)
	}
	h := sha256.Sum256([]byte(b.String()))
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
		_ = os.Remove(path)
		metrics.RecordCacheLookup(false)
		return nil
	}

	data, err := os.ReadFile(path) //nolint:gosec
	if err != nil {
		metrics.RecordCacheLookup(false)
		return nil
	}
	if len(data) == 0 {
		metrics.RecordCacheLookup(false)
		return nil
	}

	raw := json.RawMessage(data)
	metrics.RecordCacheLookup(true)
	return &raw
}

// Set stores a response in the cache.
//
// The payload may be a JSON document or a plain-text answer: providers
// without JSON mode reply with a fenced block, and rejecting it left the
// cache empty for every one of them. The write is atomic (temp file +
// rename) so concurrent Get callers never see a truncated file.
func (c *Cache) Set(key string, value json.RawMessage) error {
	if len(value) == 0 {
		return fmt.Errorf("cache value is empty")
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
		_ = os.Remove(tmpName)
		return fmt.Errorf("writing cache entry: %w", werr)
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
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
