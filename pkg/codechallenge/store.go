package codechallenge

import (
	"sync"
	"time"
)

// Store keeps the only state verification needs: how many codes were tried per challenge,
// and which challenges already gave a pass. Entries can be dropped after until, when the
// challenge expires anyway. Per edge in memory is enough (MemoryStore); a shared store
// (Redis) is only needed if several instances serve one client.
type Store interface {
	// CountAttempt records one code attempt for challenge id and returns the total so far.
	CountAttempt(id string, until time.Time) int
	// MarkUsed records that challenge id gave a pass. It returns false if it already had.
	MarkUsed(id string, until time.Time) bool
}

// MemoryStore is an in-memory Store. Expired entries are swept every sweepInterval.
type MemoryStore struct {
	mu        sync.Mutex
	entries   map[string]*storeEntry
	lastSweep time.Time
}

type storeEntry struct {
	attempts int
	used     bool
	until    time.Time
}

const sweepInterval = time.Minute

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{entries: map[string]*storeEntry{}, lastSweep: time.Now()}
}

func (s *MemoryStore) CountAttempt(id string, until time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(id, until)
	e.attempts++
	return e.attempts
}

func (s *MemoryStore) MarkUsed(id string, until time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entry(id, until)
	if e.used {
		return false
	}
	e.used = true
	return true
}

// entry returns the entry for id, creating it, and sweeps expired entries now and then.
// The caller holds s.mu.
func (s *MemoryStore) entry(id string, until time.Time) *storeEntry {
	now := time.Now()
	if now.Sub(s.lastSweep) >= sweepInterval {
		for k, e := range s.entries {
			if now.After(e.until) {
				delete(s.entries, k)
			}
		}
		s.lastSweep = now
	}
	e, ok := s.entries[id]
	if !ok {
		e = &storeEntry{until: until}
		s.entries[id] = e
	}
	return e
}
