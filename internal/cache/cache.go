// Package cache provides a small file-backed store for topology data and the
// co-occurrence history that feeds causal inference.
//
// It is deliberately not a database. Entries are JSON files under a cache
// directory, written atomically via rename. This keeps the binary
// dependency-free, makes the cache trivially inspectable with `cat` when
// debugging, and means a corrupt entry can be fixed by deleting one file.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Cache stores TTL'd JSON values on disk.
type Cache struct {
	dir string
	mu  sync.RWMutex
	// disabled short-circuits every operation, used for --no-cache.
	disabled bool
}

// entry wraps a stored value with its expiry.
type entry struct {
	ExpiresAt time.Time       `json:"expires_at"`
	Value     json.RawMessage `json:"value"`
}

// New opens (and creates if needed) a cache directory.
func New(dir string, disabled bool) (*Cache, error) {
	c := &Cache{dir: dir, disabled: disabled}
	if disabled {
		return c, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating cache dir %s: %w", dir, err)
	}
	return c, nil
}

// keyPath hashes a key into a filename so arbitrary keys (which may contain
// slashes, from PromQL expressions) are safe on disk.
func (c *Cache) keyPath(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.dir, hex.EncodeToString(sum[:16])+".json")
}

// Get decodes a cached value into out. Returns false on a miss, an expired
// entry, or any read error — a broken cache degrades to a cache miss rather
// than failing the command.
func (c *Cache) Get(key string, out any) bool {
	if c.disabled {
		return false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	data, err := os.ReadFile(c.keyPath(key))
	if err != nil {
		return false
	}
	var e entry
	if err := json.Unmarshal(data, &e); err != nil {
		return false
	}
	if time.Now().After(e.ExpiresAt) {
		return false
	}
	return json.Unmarshal(e.Value, out) == nil
}

// Set stores a value with a TTL. Write failures are returned but callers
// generally ignore them: failing to cache is never worth failing a query over.
func (c *Cache) Set(key string, value any, ttl time.Duration) error {
	if c.disabled {
		return nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encoding cache value: %w", err)
	}
	data, err := json.Marshal(entry{ExpiresAt: time.Now().Add(ttl), Value: raw})
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	path := c.keyPath(key)
	// Atomic write: a partially written cache file must never be readable, or
	// a concurrent lens process would see truncated JSON.
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return os.Rename(tmpName, path)
}

// Clear removes every cached entry.
func (c *Cache) Clear() error {
	if c.disabled {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			_ = os.Remove(filepath.Join(c.dir, e.Name()))
		}
	}
	return nil
}

// Dir reports the cache location, for `lens doctor` output.
func (c *Cache) Dir() string { return c.dir }
