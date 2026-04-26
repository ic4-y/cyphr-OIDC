package handlers

import (
	"testing"
	"time"
)

func TestChallengeStore_StoreAndGet(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	store.Store("session-1", "nonce-abc")
	got, ok := store.Get("session-1")
	if !ok {
		t.Fatal("expected to find stored nonce")
	}
	if got != "nonce-abc" {
		t.Errorf("expected nonce-abc, got %s", got)
	}
}

func TestChallengeStore_GetMissing(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("expected false for missing session")
	}
}

func TestChallengeStore_Delete(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	store.Store("session-1", "nonce-abc")
	store.Delete("session-1")

	_, ok := store.Get("session-1")
	if ok {
		t.Error("expected false after delete")
	}
}

func TestChallengeStore_DeleteMissing(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	store.Delete("nonexistent")
}

func TestChallengeStore_TTLExpiry(t *testing.T) {
	store := NewChallengeStore(50 * time.Millisecond)

	store.Store("session-1", "nonce-abc")

	// Should be immediately available
	_, ok := store.Get("session-1")
	if !ok {
		t.Fatal("expected nonce to be available immediately")
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	_, ok = store.Get("session-1")
	if ok {
		t.Error("expected nonce to be expired")
	}
}

func TestChallengeStore_Cleanup(t *testing.T) {
	store := NewChallengeStore(50 * time.Millisecond)

	store.Store("session-1", "nonce-1")
	store.Store("session-2", "nonce-2")

	time.Sleep(100 * time.Millisecond)

	store.Cleanup()

	_, ok1 := store.Get("session-1")
	_, ok2 := store.Get("session-2")

	if ok1 || ok2 {
		t.Error("expected all entries cleaned up")
	}
}

func TestChallengeStore_CleanupPreservesValid(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	store.Store("session-1", "nonce-1")
	store.Store("session-2", "nonce-2")

	store.Cleanup()

	_, ok1 := store.Get("session-1")
	_, ok2 := store.Get("session-2")

	if !ok1 || !ok2 {
		t.Error("expected valid entries to be preserved")
	}
}

func TestChallengeStore_Overwrite(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	store.Store("session-1", "nonce-old")
	store.Store("session-1", "nonce-new")

	got, ok := store.Get("session-1")
	if !ok {
		t.Fatal("expected to find stored nonce")
	}
	if got != "nonce-new" {
		t.Errorf("expected nonce-new, got %s", got)
	}
}

func TestChallengeStore_ConcurrentAccess(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	done := make(chan bool)

	for i := 0; i < 10; i++ {
		go func(id int) {
			sessionID := "session" + string(rune('0'+id))
			store.Store(sessionID, "nonce-"+string(rune('0'+id)))
			store.Get(sessionID)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestGenerateNonce_Unique(t *testing.T) {
	nonce1 := GenerateNonce()
	nonce2 := GenerateNonce()

	if nonce1 == nonce2 {
		t.Error("expected unique nonces")
	}
}

func TestGenerateNonce_Length(t *testing.T) {
	nonce := GenerateNonce()
	// 32 bytes = 64 hex characters
	if len(nonce) != 64 {
		t.Errorf("expected 64 char nonce, got %d", len(nonce))
	}
}

func TestGenerateState_Unique(t *testing.T) {
	state1 := GenerateState()
	state2 := GenerateState()

	if state1 == state2 {
		t.Error("expected unique states")
	}
}

func TestGenerateState_Length(t *testing.T) {
	state := GenerateState()
	// 16 bytes = 32 hex characters
	if len(state) != 32 {
		t.Errorf("expected 32 char state, got %d", len(state))
	}
}
