package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type ChallengeEntry struct {
	Nonce     string
	CreatedAt time.Time
}

type ChallengeStore struct {
	mu         sync.RWMutex
	challenges map[string]*ChallengeEntry
	ttl        time.Duration
}

func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	return &ChallengeStore{
		challenges: make(map[string]*ChallengeEntry),
		ttl:        ttl,
	}
}

func (s *ChallengeStore) Store(sessionID, nonce string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[sessionID] = &ChallengeEntry{
		Nonce:     nonce,
		CreatedAt: time.Now(),
	}
}

func (s *ChallengeStore) Get(sessionID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.challenges[sessionID]
	if !ok {
		return "", false
	}
	if time.Since(entry.CreatedAt) > s.ttl {
		delete(s.challenges, sessionID)
		return "", false
	}
	return entry.Nonce, true
}

func (s *ChallengeStore) Delete(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.challenges, sessionID)
}

func (s *ChallengeStore) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, entry := range s.challenges {
		if now.Sub(entry.CreatedAt) > s.ttl {
			delete(s.challenges, id)
		}
	}
}

func GenerateNonce() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func GenerateState() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
