package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

func TestTokenCallbackHandler_MissingCode(t *testing.T) {
	oidcStore := storage.NewStorage()
	handler := NewTokenCallbackHandler(oidcStore)

	req := httptest.NewRequest("GET", "/callback", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing code, got %d", rr.Code)
	}
}

func TestTokenCallbackHandler_InvalidCode(t *testing.T) {
	oidcStore := storage.NewStorage()
	handler := NewTokenCallbackHandler(oidcStore)

	req := httptest.NewRequest("GET", "/callback?code=invalid", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid code, got %d", rr.Code)
	}
}

func TestTokenCallbackHandler_Success(t *testing.T) {
	oidcStore := storage.NewStorage()

	_, err := oidcStore.TestCreateAuthRequest(context.Background(), "auth-1", "test-client", "http://localhost/callback", "state-xyz", "nonce-123")
	if err != nil {
		t.Fatalf("failed to create test auth request: %v", err)
	}
	oidcStore.CompleteTestAuthRequest("auth-1", "user-1", "user@example.com")
	oidcStore.SaveAuthCode(nil, "auth-1", "valid-code")

	handler := NewTokenCallbackHandler(oidcStore)

	req := httptest.NewRequest("GET", "/callback?code=valid-code&state=state-xyz", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "Authentication Successful") {
		t.Error("response should contain success message")
	}
	if !strings.Contains(body, "user-1") {
		t.Error("response should contain subject")
	}
	if !strings.Contains(body, "state-xyz") {
		t.Error("response should contain state")
	}
}
