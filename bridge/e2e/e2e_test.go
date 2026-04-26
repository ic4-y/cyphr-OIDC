package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/handlers"
	"github.com/ic4y/cyphrmask-oidc-poc/bridge/internal/testutil"
)

func TestE2E_FullFlow(t *testing.T) {
	key := testutil.NewTestKey(t)
	challengeStore := testutil.NewTestChallengeStore(t)
	oidcStore := testutil.NewTestOIDCStorage(t, "http://localhost/callback")
	usersJSON := testutil.BuildUsersJSON(map[testutil.TestKey]string{key: ""})

	challengeHandler := handlers.HandleChallenge(challengeStore)
	challengeReq := httptest.NewRequest("GET", "/api/challenge", nil)
	challengeReq.RemoteAddr = "192.168.1.100:12345"
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)

	if challengeRR.Code != http.StatusOK {
		t.Fatalf("challenge failed: %d", challengeRR.Code)
	}

	var challengeResp map[string]string
	if err := json.NewDecoder(challengeRR.Body).Decode(&challengeResp); err != nil {
		t.Fatalf("failed to decode challenge: %v", err)
	}

	nonce := challengeResp["nonce"]
	if nonce == "" {
		t.Fatal("expected nonce in challenge response")
	}

	cozPayload := testutil.SignCozPayload(t, key.PrivateKey, nonce, key.Thumbprint)

	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)
	verifyReq := httptest.NewRequest("POST", "/api/verify?authRequestID=test-req", bytes.NewReader([]byte(cozPayload)))
	verifyReq.RemoteAddr = "192.168.1.100:12345"
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusOK {
		t.Fatalf("verify failed: %d, body: %s", verifyRR.Code, verifyRR.Body.String())
	}

	var verifyResp map[string]string
	if err := json.NewDecoder(verifyRR.Body).Decode(&verifyResp); err != nil {
		t.Fatalf("failed to decode verify response: %v", err)
	}

	if verifyResp["email"] != "test@example.com" {
		t.Errorf("expected email test@example.com, got %s", verifyResp["email"])
	}
	if verifyResp["tmb"] != key.Thumbprint {
		t.Errorf("expected thumbprint %s, got %s", key.Thumbprint, verifyResp["tmb"])
	}
}

func TestE2E_ChallengeThenVerifyWithWrongNonce(t *testing.T) {
	key := testutil.NewTestKey(t)
	challengeStore := testutil.NewTestChallengeStore(t)
	oidcStore := testutil.NewTestOIDCStorage(t, "http://localhost/callback")
	usersJSON := testutil.BuildUsersJSON(map[testutil.TestKey]string{key: ""})

	challengeStore.Store("192.168.1.100:12345", "stored-nonce")

	cozPayload := testutil.SignCozPayload(t, key.PrivateKey, "wrong-nonce", key.Thumbprint)

	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)
	verifyReq := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq.RemoteAddr = "192.168.1.100:12345"
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for nonce mismatch, got %d", verifyRR.Code)
	}
}

func TestE2E_ChallengeThenVerifyWithUnknownKey(t *testing.T) {
	key := testutil.NewTestKey(t)
	challengeStore := testutil.NewTestChallengeStore(t)

	challengeHandler := handlers.HandleChallenge(challengeStore)
	challengeReq := httptest.NewRequest("GET", "/api/challenge", nil)
	challengeReq.RemoteAddr = "192.168.1.100:12345"
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)

	var challengeResp map[string]string
	json.NewDecoder(challengeRR.Body).Decode(&challengeResp)

	cozPayload := testutil.SignCozPayload(t, key.PrivateKey, challengeResp["nonce"], key.Thumbprint)

	verifyHandler := handlers.HandleVerify(challengeStore, nil, "")
	verifyReq := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq.RemoteAddr = "192.168.1.100:12345"
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown key, got %d", verifyRR.Code)
	}
}

func TestE2E_ReplayProtection(t *testing.T) {
	key := testutil.NewTestKey(t)
	challengeStore := testutil.NewTestChallengeStore(t)
	oidcStore := testutil.NewTestOIDCStorage(t, "http://localhost/callback")
	usersJSON := testutil.BuildUsersJSON(map[testutil.TestKey]string{key: ""})

	challengeStore.Store("192.168.1.100:12345", "replay-nonce")

	cozPayload := testutil.SignCozPayload(t, key.PrivateKey, "replay-nonce", key.Thumbprint)
	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)

	verifyReq1 := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq1.RemoteAddr = "192.168.1.100:12345"
	verifyRR1 := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR1, verifyReq1)

	if verifyRR1.Code != http.StatusOK {
		t.Fatalf("first verify failed: %d", verifyRR1.Code)
	}

	verifyReq2 := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq2.RemoteAddr = "192.168.1.100:12345"
	verifyRR2 := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR2, verifyReq2)

	if verifyRR2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for replayed nonce, got %d", verifyRR2.Code)
	}
}

func TestE2E_TimelinessCheck(t *testing.T) {
	key := testutil.NewTestKey(t)
	challengeStore := testutil.NewTestChallengeStore(t)
	oidcStore := testutil.NewTestOIDCStorage(t, "http://localhost/callback")
	usersJSON := testutil.BuildUsersJSON(map[testutil.TestKey]string{key: ""})

	challengeStore.Store("192.168.1.100:12345", "timely-nonce")

	now := time.Now().Add(-2 * time.Hour).Unix()

	cozPayload := testutil.SignCozPayloadAtTime(t, key.PrivateKey, "timely-nonce", key.Thumbprint, now)

	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)
	verifyReq := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq.RemoteAddr = "192.168.1.100:12345"
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired timestamp, got %d", verifyRR.Code)
	}
}

func TestE2E_MultipleUsers(t *testing.T) {
	key1 := testutil.NewTestKey(t)
	key2 := testutil.NewTestKey(t)

	challengeStore := testutil.NewTestChallengeStore(t)
	oidcStore := testutil.NewTestOIDCStorage(t, "http://localhost/callback")

	usersJSON := testutil.BuildUsersJSON(map[testutil.TestKey]string{
		key1: "user1@example.com",
		key2: "user2@example.com",
	})

	challengeStore.Store("192.168.1.100:12345", "user1-nonce")
	coz1 := testutil.SignCozPayload(t, key1.PrivateKey, "user1-nonce", key1.Thumbprint)

	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)
	req1 := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(coz1)))
	req1.RemoteAddr = "192.168.1.100:12345"
	rr1 := httptest.NewRecorder()
	verifyHandler.ServeHTTP(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("key1 verify failed: %d", rr1.Code)
	}

	var resp1 map[string]string
	json.NewDecoder(rr1.Body).Decode(&resp1)
	if resp1["email"] != "user1@example.com" {
		t.Errorf("expected user1 email, got %s", resp1["email"])
	}

	challengeStore.Store("192.168.1.100:54321", "user2-nonce")
	coz2 := testutil.SignCozPayload(t, key2.PrivateKey, "user2-nonce", key2.Thumbprint)

	req2 := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(coz2)))
	req2.RemoteAddr = "192.168.1.100:54321"
	rr2 := httptest.NewRecorder()
	verifyHandler.ServeHTTP(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("key2 verify failed: %d", rr2.Code)
	}

	var resp2 map[string]string
	json.NewDecoder(rr2.Body).Decode(&resp2)
	if resp2["email"] != "user2@example.com" {
		t.Errorf("expected user2 email, got %s", resp2["email"])
	}
}
