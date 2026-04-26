package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/handlers"
	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

type testKey struct {
	privateKey *ecdsa.PrivateKey
	publicKey  string
	thumbprint string
}

func setupTestKey(t *testing.T) testKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	// Compute thumbprint per RFC 7638
	jwkBytes := []byte(`{"crv":"P-256","kty":"EC","x":"` + base64.RawURLEncoding.EncodeToString(xPadded) + `","y":"` + base64.RawURLEncoding.EncodeToString(yPadded) + `"}`)
	hash := sha256.Sum256(jwkBytes)
	tmb := base64.RawURLEncoding.EncodeToString(hash[:])

	// Create raw uncompressed public key (0x04 || X || Y) as hex
	rawBytes := append([]byte{0x04}, append(xPadded, yPadded...)...)
	pubHex := hex.EncodeToString(rawBytes)

	return testKey{
		privateKey: key,
		publicKey:  pubHex,
		thumbprint: tmb,
	}
}

func signCozPayload(t *testing.T, key *ecdsa.PrivateKey, nonce, tmb string) string {
	t.Helper()
	now := time.Now().Unix()

	pay := map[string]interface{}{
		"alg":   "ES256",
		"tmb":   tmb,
		"typ":   "cyphr/auth/challenge",
		"now":   now,
		"nonce": nonce,
	}

	payBytes, err := json.Marshal(pay)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}

	hash := sha256.Sum256(payBytes)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := append(rBytes, sBytes...)
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)

	envelope := map[string]interface{}{
		"pay": pay,
		"sig": sig,
	}

	envelopeBytes, err := json.Marshal(envelope)
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}

	return string(envelopeBytes)
}

func TestE2E_FullFlow(t *testing.T) {
	key := setupTestKey(t)

	// Set up stores
	challengeStore := handlers.NewChallengeStore(time.Minute * 5)
	oidcStore := storage.NewStorage()
	oidcStore.RegisterClient(storage.NewClient("test-client", "secret", []string{"http://localhost/callback"}, func(id string) string {
		return "/login?authRequestID=" + id
	}))

	usersJSON := `{"` + key.thumbprint + `":{"email":"test@example.com","public_key":"` + key.publicKey + `"}}`

	// Challenge endpoint
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

	// Sign the challenge
	cozPayload := signCozPayload(t, key.privateKey, nonce, key.thumbprint)

	// Verify endpoint
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
	if verifyResp["tmb"] != key.thumbprint {
		t.Errorf("expected thumbprint %s, got %s", key.thumbprint, verifyResp["tmb"])
	}
}

func TestE2E_ChallengeThenVerifyWithWrongNonce(t *testing.T) {
	key := setupTestKey(t)

	challengeStore := handlers.NewChallengeStore(time.Minute * 5)
	oidcStore := storage.NewStorage()

	usersJSON := `{"` + key.thumbprint + `":{"email":"test@example.com","public_key":"` + key.publicKey + `"}}`

	// Store a nonce
	challengeStore.Store("192.168.1.100:12345", "stored-nonce")

	// Sign with a different nonce
	cozPayload := signCozPayload(t, key.privateKey, "wrong-nonce", key.thumbprint)

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
	key := setupTestKey(t)

	challengeStore := handlers.NewChallengeStore(time.Minute * 5)
	oidcStore := storage.NewStorage()

	// Challenge to get a nonce
	challengeHandler := handlers.HandleChallenge(challengeStore)
	challengeReq := httptest.NewRequest("GET", "/api/challenge", nil)
	challengeReq.RemoteAddr = "192.168.1.100:12345"
	challengeRR := httptest.NewRecorder()
	challengeHandler.ServeHTTP(challengeRR, challengeReq)

	var challengeResp map[string]string
	json.NewDecoder(challengeRR.Body).Decode(&challengeResp)

	// Sign with the key, but the key is not in the user store
	cozPayload := signCozPayload(t, key.privateKey, challengeResp["nonce"], key.thumbprint)

	// Empty user store
	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, "")
	verifyReq := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq.RemoteAddr = "192.168.1.100:12345"
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for unknown key, got %d", verifyRR.Code)
	}
}

func TestE2E_ReplayProtection(t *testing.T) {
	key := setupTestKey(t)

	challengeStore := handlers.NewChallengeStore(time.Minute * 5)
	oidcStore := storage.NewStorage()

	usersJSON := `{"` + key.thumbprint + `":{"email":"test@example.com","public_key":"` + key.publicKey + `"}}`

	// Get a nonce
	challengeStore.Store("192.168.1.100:12345", "replay-nonce")

	// Sign and verify once
	cozPayload := signCozPayload(t, key.privateKey, "replay-nonce", key.thumbprint)

	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)

	// First request
	verifyReq1 := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq1.RemoteAddr = "192.168.1.100:12345"
	verifyRR1 := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR1, verifyReq1)

	if verifyRR1.Code != http.StatusOK {
		t.Fatalf("first verify failed: %d", verifyRR1.Code)
	}

	// Second request (replay) - nonce should be deleted after first use
	verifyReq2 := httptest.NewRequest("POST", "/api/verify", bytes.NewReader([]byte(cozPayload)))
	verifyReq2.RemoteAddr = "192.168.1.100:12345"
	verifyRR2 := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR2, verifyReq2)

	if verifyRR2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for replayed nonce, got %d", verifyRR2.Code)
	}
}

func TestE2E_TimelinessCheck(t *testing.T) {
	key := setupTestKey(t)

	challengeStore := handlers.NewChallengeStore(time.Minute * 5)
	oidcStore := storage.NewStorage()

	usersJSON := `{"` + key.thumbprint + `":{"email":"test@example.com","public_key":"` + key.publicKey + `"}}`

	// Get a nonce
	challengeStore.Store("192.168.1.100:12345", "timely-nonce")

	// Sign with a timestamp from 2 hours ago
	now := time.Now().Add(-2 * time.Hour).Unix()

	pay := map[string]interface{}{
		"alg":   "ES256",
		"tmb":   key.thumbprint,
		"typ":   "cyphr/auth/challenge",
		"now":   now,
		"nonce": "timely-nonce",
	}
	payBytes, _ := json.Marshal(pay)
	hash := sha256.Sum256(payBytes)
	r, s, _ := ecdsa.Sign(rand.Reader, key.privateKey, hash[:])
	sigBytes := append(r.Bytes(), s.Bytes()...)
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)

	envelope := map[string]interface{}{
		"pay": pay,
		"sig": sig,
	}
	cozPayload, _ := json.Marshal(envelope)

	verifyHandler := handlers.HandleVerify(challengeStore, oidcStore, usersJSON)
	verifyReq := httptest.NewRequest("POST", "/api/verify", bytes.NewReader(cozPayload))
	verifyReq.RemoteAddr = "192.168.1.100:12345"
	verifyRR := httptest.NewRecorder()
	verifyHandler.ServeHTTP(verifyRR, verifyReq)

	if verifyRR.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for expired timestamp, got %d", verifyRR.Code)
	}
}

func TestE2E_MultipleUsers(t *testing.T) {
	key1 := setupTestKey(t)
	key2 := setupTestKey(t)

	challengeStore := handlers.NewChallengeStore(time.Minute * 5)
	oidcStore := storage.NewStorage()

	usersJSON := `{"` + key1.thumbprint + `":{"email":"user1@example.com","public_key":"` + key1.publicKey + `"},"` + key2.thumbprint + `":{"email":"user2@example.com","public_key":"` + key2.publicKey + `"}}`

	// Test with key1
	challengeStore.Store("192.168.1.100:12345", "user1-nonce")
	coz1 := signCozPayload(t, key1.privateKey, "user1-nonce", key1.thumbprint)

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

	// Test with key2
	challengeStore.Store("192.168.1.100:54321", "user2-nonce")
	coz2 := signCozPayload(t, key2.privateKey, "user2-nonce", key2.thumbprint)

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
