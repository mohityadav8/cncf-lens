package cache

import (
	"sync"
	"time"
)

// historyKey is the co-occurrence counter file name.
const historyKey = "causal-history-v1"

// historyTTL is long because this data is meant to accumulate. It exists at all
// so that a cluster rebuilt from scratch eventually forgets stale patterns.
const historyTTL = 30 * 24 * time.Hour

// historyData is the persisted shape.
type historyData struct {
	// Together counts "cause of kind A preceded anomaly of kind B", keyed by
	// "causeKey|anomalyKey".
	Together map[string]int `json:"together"`
	// CauseTotals counts how often each cause kind was observed at all, which
	// is the denominator that stops common events looking causal.
	CauseTotals map[string]int `json:"cause_totals"`
	UpdatedAt   time.Time      `json:"updated_at"`
}

// History implements correlate.History on top of the file cache.
type History struct {
	cache *Cache
	mu    sync.RWMutex
	data  historyData
	dirty bool
}

// NewHistory loads existing co-occurrence data, or starts empty.
func NewHistory(c *Cache) *History {
	h := &History{
		cache: c,
		data: historyData{
			Together:    map[string]int{},
			CauseTotals: map[string]int{},
		},
	}
	var loaded historyData
	if c.Get(historyKey, &loaded) {
		if loaded.Together != nil {
			h.data.Together = loaded.Together
		}
		if loaded.CauseTotals != nil {
			h.data.CauseTotals = loaded.CauseTotals
		}
		h.data.UpdatedAt = loaded.UpdatedAt
	}
	return h
}

// CoOccurrences satisfies correlate.History.
func (h *History) CoOccurrences(causeKey, anomalyKey string) (together, causeTotal int) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.data.Together[causeKey+"|"+anomalyKey], h.data.CauseTotals[causeKey]
}

// Record notes that a cause preceded an anomaly. Called after each diagnose run
// so the tool gets better at this specific cluster over time.
func (h *History) Record(causeKey, anomalyKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data.Together[causeKey+"|"+anomalyKey]++
	h.data.CauseTotals[causeKey]++
	h.dirty = true
}

// RecordCauseSeen increments only the denominator, for causes observed that did
// not precede the anomaly. Without this the ratio would always be 1.0 and the
// historical rule would fire on everything.
func (h *History) RecordCauseSeen(causeKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.data.CauseTotals[causeKey]++
	h.dirty = true
}

// Flush persists any changes. Errors are returned but callers may ignore them.
func (h *History) Flush() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.dirty {
		return nil
	}
	h.data.UpdatedAt = time.Now().UTC()
	h.dirty = false
	return h.cache.Set(historyKey, h.data, historyTTL)
}
