package cache

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type payload struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

func TestSetAndGetRoundTrip(t *testing.T) {
	c, err := New(t.TempDir(), false)
	if err != nil {
		t.Fatal(err)
	}
	want := payload{Name: "topology", Count: 42}
	if err := c.Set("k", want, time.Minute); err != nil {
		t.Fatal(err)
	}
	var got payload
	if !c.Get("k", &got) {
		t.Fatal("cache miss immediately after Set")
	}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestGetMissesOnExpiry(t *testing.T) {
	c, _ := New(t.TempDir(), false)
	if err := c.Set("k", payload{Name: "stale"}, -time.Second); err != nil {
		t.Fatal(err)
	}
	var got payload
	if c.Get("k", &got) {
		t.Error("an expired entry was served")
	}
}

func TestGetMissesOnUnknownKey(t *testing.T) {
	c, _ := New(t.TempDir(), false)
	var got payload
	if c.Get("never-written", &got) {
		t.Error("unknown key reported a hit")
	}
}

// A corrupt cache file must degrade to a miss, never fail the command.
func TestCorruptEntryDegradesToMiss(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(dir, false)
	if err := c.Set("k", payload{Name: "x"}, time.Minute); err != nil {
		t.Fatal(err)
	}

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			if err := os.WriteFile(filepath.Join(dir, e.Name()), []byte("{{{ not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	var got payload
	if c.Get("k", &got) {
		t.Error("a corrupt entry was served as a hit")
	}
}

func TestDisabledCacheIsANoOp(t *testing.T) {
	c, err := New(filepath.Join(t.TempDir(), "never-created"), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Set("k", payload{Name: "x"}, time.Minute); err != nil {
		t.Errorf("Set on a disabled cache should be a silent no-op: %v", err)
	}
	var got payload
	if c.Get("k", &got) {
		t.Error("a disabled cache returned a hit")
	}
}

func TestClearRemovesEntries(t *testing.T) {
	c, _ := New(t.TempDir(), false)
	_ = c.Set("a", payload{Name: "a"}, time.Minute)
	_ = c.Set("b", payload{Name: "b"}, time.Minute)

	if err := c.Clear(); err != nil {
		t.Fatal(err)
	}
	var got payload
	if c.Get("a", &got) || c.Get("b", &got) {
		t.Error("entries survived Clear")
	}
}

// Cached data can include credentials-adjacent topology, so files must not be
// world-readable.
func TestCacheFilesAreNotWorldReadable(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(dir, false)
	_ = c.Set("k", payload{Name: "x"}, time.Minute)

	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has permissions %o, want 0600", e.Name(), info.Mode().Perm())
		}
	}
}

// Keys may contain slashes and quotes (PromQL expressions do), which must not
// escape the cache directory.
func TestKeysWithPathCharactersAreSafe(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(dir, false)

	key := `../../etc/passwd{job="x"}/rate[5m]`
	if err := c.Set(key, payload{Name: "safe"}, time.Minute); err != nil {
		t.Fatal(err)
	}
	var got payload
	if !c.Get(key, &got) || got.Name != "safe" {
		t.Error("round trip failed for a key with path characters")
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "etc", "passwd")); err == nil {
		t.Fatal("cache key escaped the cache directory")
	}
}

func TestConcurrentAccessIsSafe(t *testing.T) {
	c, _ := New(t.TempDir(), false)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = c.Set("shared", payload{Count: i}, time.Minute)
			var got payload
			c.Get("shared", &got)
		}(i)
	}
	wg.Wait()
}

func TestHistoryPersistsAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	c, _ := New(dir, false)

	h := NewHistory(c)
	for i := 0; i < 5; i++ {
		h.Record("kubernetes/deploy/payments", "prometheus/metric/payments/checkout")
	}
	if err := h.Flush(); err != nil {
		t.Fatal(err)
	}

	// A fresh process must see the accumulated counts.
	c2, _ := New(dir, false)
	h2 := NewHistory(c2)
	together, total := h2.CoOccurrences("kubernetes/deploy/payments", "prometheus/metric/payments/checkout")
	if together != 5 || total != 5 {
		t.Errorf("history did not persist: together=%d total=%d", together, total)
	}
}

// The denominator must grow independently, or every cause would show a 100%
// co-occurrence ratio and the historical rule would fire on everything.
func TestRecordCauseSeenGrowsDenominatorOnly(t *testing.T) {
	c, _ := New(t.TempDir(), false)
	h := NewHistory(c)

	h.Record("cause-a", "anomaly-x")
	for i := 0; i < 9; i++ {
		h.RecordCauseSeen("cause-a")
	}

	together, total := h.CoOccurrences("cause-a", "anomaly-x")
	if together != 1 {
		t.Errorf("together = %d, want 1", together)
	}
	if total != 10 {
		t.Errorf("total = %d, want 10", total)
	}
}
