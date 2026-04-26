package storage

import (
	"context"
	"testing"

	"github.com/zitadel/oidc/v3/pkg/op"
)

func TestNewStorage_CreatesSigningKey(t *testing.T) {
	s := NewStorage()
	if s.signingKey.key == nil {
		t.Error("signing key should not be nil")
	}
}

func TestRegisterClient(t *testing.T) {
	s := NewStorage()
	s.RegisterClient(NewClient("client-1", "secret-1", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	client, err := s.GetClientByClientID(context.Background(), "client-1")
	if err != nil {
		t.Fatalf("failed to get client: %v", err)
	}
	if client.GetID() != "client-1" {
		t.Errorf("expected client-1, got %s", client.GetID())
	}
}

func TestAuthorizeClientIDSecret_Valid(t *testing.T) {
	s := NewStorage()
	s.RegisterClient(NewClient("client-1", "secret-1", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	err := s.AuthorizeClientIDSecret(context.Background(), "client-1", "secret-1")
	if err != nil {
		t.Errorf("expected no error for valid secret, got: %v", err)
	}
}

func TestAuthorizeClientIDSecret_Invalid(t *testing.T) {
	s := NewStorage()
	s.RegisterClient(NewClient("client-1", "secret-1", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	err := s.AuthorizeClientIDSecret(context.Background(), "client-1", "wrong-secret")
	if err == nil {
		t.Error("expected error for wrong secret")
	}
}

func TestAuthorizeClientIDSecret_UnknownClient(t *testing.T) {
	s := NewStorage()

	err := s.AuthorizeClientIDSecret(context.Background(), "unknown", "secret")
	if err == nil {
		t.Error("expected error for unknown client")
	}
}

func TestCreateAuthRequest(t *testing.T) {
	s := NewStorage()
	s.RegisterClient(NewClient("client-1", "secret-1", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	result, err := s.TestCreateAuthRequest(context.Background(), "test-req", "client-1", "http://localhost/callback", "state-1", "nonce-1")
	if err != nil {
		t.Fatalf("failed to create auth request: %v", err)
	}

	if result.GetID() != "test-req" {
		t.Errorf("expected test-req, got %s", result.GetID())
	}
	if result.GetClientID() != "client-1" {
		t.Errorf("expected client-1, got %s", result.GetClientID())
	}
	if result.GetState() != "state-1" {
		t.Errorf("expected state-1, got %s", result.GetState())
	}
	if result.GetNonce() != "nonce-1" {
		t.Errorf("expected nonce-1, got %s", result.GetNonce())
	}
}

func TestAuthRequestByID_Found(t *testing.T) {
	s := NewStorage()
	s.CreateTestAuthRequest("req-1", "client-1", "http://localhost/callback", "state-1")

	result, err := s.AuthRequestByID(context.Background(), "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.GetID() != "req-1" {
		t.Errorf("expected req-1, got %s", result.GetID())
	}
}

func TestAuthRequestByID_NotFound(t *testing.T) {
	s := NewStorage()

	_, err := s.AuthRequestByID(context.Background(), "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent request")
	}
}

func TestSaveAuthCode(t *testing.T) {
	s := NewStorage()
	s.CreateTestAuthRequest("req-1", "client-1", "http://localhost/callback", "state-1")

	err := s.SaveAuthCode(context.Background(), "req-1", "code-abc")
	if err != nil {
		t.Fatalf("failed to save auth code: %v", err)
	}

	requestID, ok := s.AuthCodeByRequestID("code-abc")
	if !ok {
		t.Fatal("expected to find code")
	}
	if requestID != "req-1" {
		t.Errorf("expected req-1, got %s", requestID)
	}
}

func TestAuthRequestByCode_Valid(t *testing.T) {
	s := NewStorage()
	s.CreateTestAuthRequest("req-1", "client-1", "http://localhost/callback", "state-1")
	s.SaveAuthCode(context.Background(), "req-1", "code-abc")

	result, err := s.AuthRequestByCode(context.Background(), "code-abc")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.GetID() != "req-1" {
		t.Errorf("expected req-1, got %s", result.GetID())
	}
}

func TestAuthRequestByCode_Invalid(t *testing.T) {
	s := NewStorage()

	_, err := s.AuthRequestByCode(context.Background(), "invalid-code")
	if err == nil {
		t.Error("expected error for invalid code")
	}
}

func TestDeleteAuthRequest(t *testing.T) {
	s := NewStorage()
	s.CreateTestAuthRequest("req-1", "client-1", "http://localhost/callback", "state-1")
	s.SaveAuthCode(context.Background(), "req-1", "code-abc")

	err := s.DeleteAuthRequest(context.Background(), "req-1")
	if err != nil {
		t.Fatalf("failed to delete: %v", err)
	}

	_, err = s.AuthRequestByID(context.Background(), "req-1")
	if err == nil {
		t.Error("expected request to be deleted")
	}

	_, err = s.AuthRequestByCode(context.Background(), "code-abc")
	if err == nil {
		t.Error("expected code to be deleted with request")
	}
}

func TestCompleteAuthRequest(t *testing.T) {
	s := NewStorage()
	s.CreateTestAuthRequest("req-1", "client-1", "http://localhost/callback", "state-1")

	s.CompleteTestAuthRequest("req-1", "user-123", "user@example.com")

	result, _ := s.AuthRequestByID(context.Background(), "req-1")
	if result.GetSubject() != "user-123" {
		t.Errorf("expected subject user-123, got %s", result.GetSubject())
	}
	if !result.Done() {
		t.Error("expected request to be marked as done")
	}
}

func TestCheckUsernamePassword(t *testing.T) {
	s := NewStorage()
	s.CreateTestAuthRequest("req-1", "client-1", "http://localhost/callback", "state-1")

	err := s.CheckUsernamePassword("user", "pass", "req-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	result, _ := s.AuthRequestByID(context.Background(), "req-1")
	if !result.Done() {
		t.Error("expected request to be marked as done after login")
	}
}

func TestCheckUsernamePassword_NotFound(t *testing.T) {
	s := NewStorage()

	err := s.CheckUsernamePassword("user", "pass", "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent request")
	}
}

func TestHealth(t *testing.T) {
	s := NewStorage()

	err := s.Health(context.Background())
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestClient_GetID(t *testing.T) {
	c := NewClient("my-client", "secret", []string{"http://localhost/callback"}, func(id string) string {
		return "/login"
	})

	if c.GetID() != "my-client" {
		t.Errorf("expected my-client, got %s", c.GetID())
	}
}

func TestClient_ApplicationType(t *testing.T) {
	c := NewClient("my-client", "secret", []string{"http://localhost/callback"}, func(id string) string {
		return "/login"
	})

	if c.ApplicationType() != op.ApplicationTypeWeb {
		t.Errorf("expected web application type")
	}
}
