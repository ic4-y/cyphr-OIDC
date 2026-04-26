package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

func TestCallbackHandler_MissingAuthRequestID(t *testing.T) {
	oidcStore := storage.NewStorage()
	handler := NewCallbackHandler(oidcStore)

	req := httptest.NewRequest("GET", "/callback", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing auth request id, got %d", rr.Code)
	}
}

func TestCallbackHandler_InvalidAuthRequestID(t *testing.T) {
	oidcStore := storage.NewStorage()
	handler := NewCallbackHandler(oidcStore)

	req := httptest.NewRequest("GET", "/callback?id=nonexistent", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid auth request id, got %d", rr.Code)
	}
}

func TestCallbackHandler_Success(t *testing.T) {
	oidcStore := storage.NewStorage()
	oidcStore.RegisterClient(storage.NewClient("test-client", "secret", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	oidcStore.CreateTestAuthRequest("test-auth-req", "test-client", "http://localhost/callback", "test-state")

	handler := NewCallbackHandler(oidcStore)

	req := httptest.NewRequest("GET", "/callback?id=test-auth-req", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect, got %d", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}

	if !strings.Contains(location, "code=") {
		t.Error("redirect URL should contain code parameter")
	}
	if !strings.Contains(location, "state=test-state") {
		t.Error("redirect URL should contain state=test-state")
	}

	if !strings.HasPrefix(location, "http://localhost/callback?") {
		t.Errorf("redirect should be to client redirect URI, got %s", location)
	}
}

func TestGenCode_Unique(t *testing.T) {
	code1 := genCode()
	code2 := genCode()

	if code1 == code2 {
		t.Error("generated codes should be unique")
	}
}

func TestGenCode_Length(t *testing.T) {
	code := genCode()
	// 32 bytes = 43 base64url chars (no padding)
	if len(code) != 43 {
		t.Errorf("expected 43 char code, got %d", len(code))
	}
}
