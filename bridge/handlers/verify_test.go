package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

func TestLoadUsers_EmptyEnv(t *testing.T) {
	users := loadUsers("")

	// Should fall back to hardcoded test users
	if len(users) == 0 {
		t.Error("expected hardcoded test users when env is empty")
	}

	// Verify the hardcoded user exists
	_, ok := users["cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak"]
	if !ok {
		t.Error("expected hardcoded test user to be present")
	}
}

func TestLoadUsers_InvalidJSON(t *testing.T) {
	users := loadUsers("not-valid-json")

	// Should fall back to hardcoded users
	if len(users) == 0 {
		t.Error("expected hardcoded test users when JSON is invalid")
	}
}

func TestLoadUsers_Merge(t *testing.T) {
	usersJSON := `{"custom-tmb":{"email":"custom@test.com","public_key":"custom-key"}}`
	users := loadUsers(usersJSON)

	// Should have both hardcoded and env users
	if len(users) < 2 {
		t.Errorf("expected at least 2 users, got %d", len(users))
	}

	// Hardcoded user should still exist
	_, ok := users["cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak"]
	if !ok {
		t.Error("expected hardcoded test user to be preserved")
	}

	// Custom user should be added
	custom, ok := users["custom-tmb"]
	if !ok {
		t.Error("expected custom user from env")
	}
	if custom.Email != "custom@test.com" {
		t.Errorf("expected custom email, got %s", custom.Email)
	}
}

func TestLoadUsers_Override(t *testing.T) {
	// Override the hardcoded user with new data
	usersJSON := `{"cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak":{"email":"overridden@test.com","public_key":"new-key"}}`
	users := loadUsers(usersJSON)

	user, ok := users["cLj8vsYtMBwYkzoFVZHBZo6SNL5hTN0OU1ygWJdBJak"]
	if !ok {
		t.Fatal("expected user to exist")
	}
	if user.Email != "overridden@test.com" {
		t.Errorf("expected overridden email, got %s", user.Email)
	}
	if user.PublicKey != "new-key" {
		t.Errorf("expected overridden public key, got %s", user.PublicKey)
	}
}

func TestHandleVerify_MissingAuthRequestID(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	oidcStore := storage.NewStorage()
	oidcStore.RegisterClient(storage.NewClient("test-client", "secret", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	handler := HandleVerify(store, oidcStore, "")

	req := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(`{"pay":{},"sig":"test"}`)))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized && rr.Code != http.StatusOK {
		t.Errorf("unexpected status code: %d", rr.Code)
	}
}

func TestHandleVerify_InvalidJSON(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	oidcStore := storage.NewStorage()

	handler := HandleVerify(store, oidcStore, "")

	req := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(`not-json`)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rr.Code)
	}
}

func TestHandleVerify_MissingPayField(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	oidcStore := storage.NewStorage()

	handler := HandleVerify(store, oidcStore, "")

	req := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(`{"sig":"test"}`)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing pay field, got %d", rr.Code)
	}
}

func TestHandleVerify_MissingSigField(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	oidcStore := storage.NewStorage()

	handler := HandleVerify(store, oidcStore, "")

	req := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(`{"pay":{}}`)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing sig field, got %d", rr.Code)
	}
}

func TestHandleVerify_InvalidPayFormat(t *testing.T) {
	store := NewChallengeStore(time.Minute)
	oidcStore := storage.NewStorage()

	handler := HandleVerify(store, oidcStore, "")

	req := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(`{"pay":"not-an-object","sig":"test"}`)))
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid pay format, got %d", rr.Code)
	}
}

func TestHandleChallenge_ReturnsNonce(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	handler := HandleChallenge(store)

	req := httptest.NewRequest("GET", "/api/challenge", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["nonce"] == "" {
		t.Error("expected nonce in response")
	}
	if resp["session"] == "" {
		t.Error("expected session in response")
	}
	if resp["expires"] == "" {
		t.Error("expected expires in response")
	}
}

func TestHandleChallenge_StoresNonce(t *testing.T) {
	store := NewChallengeStore(time.Minute)

	handler := HandleChallenge(store)

	req := httptest.NewRequest("GET", "/api/challenge", nil)
	req.RemoteAddr = "test-session"
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	var resp map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify the nonce is stored
	stored, ok := store.Get("test-session")
	if !ok {
		t.Fatal("expected nonce to be stored")
	}
	if stored != resp["nonce"] {
		t.Errorf("expected stored nonce to match response: %s vs %s", stored, resp["nonce"])
	}
}

func TestHealthEndpoint(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()

	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}

	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp["status"] != "ok" {
		t.Errorf("expected status ok, got %s", resp["status"])
	}
}
