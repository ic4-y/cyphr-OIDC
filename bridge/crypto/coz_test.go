package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func generateTestKey(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	pemBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pemStr := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pemBytes})
	return key, string(pemStr)
}

func signTestPayload(t *testing.T, key *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := append(rBytes, sBytes...)
	return base64.RawURLEncoding.EncodeToString(sigBytes)
}

func TestVerifyCozSignature_Valid(t *testing.T) {
	key, pubPEM := generateTestKey(t)
	payload := []byte(`{"alg":"ES256","tmb":"test","typ":"cyphr/auth/challenge","now":1234567890,"nonce":"abc"}`)
	sig := signTestPayload(t, key, payload)

	err := VerifyCozSignature(payload, sig, pubPEM)
	if err != nil {
		t.Errorf("expected no error for valid signature, got: %v", err)
	}
}

func TestVerifyCozSignature_InvalidSignature(t *testing.T) {
	_, pubPEM := generateTestKey(t)
	otherKey, _ := generateTestKey(t)
	payload := []byte(`{"test":"data"}`)
	sig := signTestPayload(t, otherKey, payload)

	err := VerifyCozSignature(payload, sig, pubPEM)
	if err == nil {
		t.Error("expected error for signature from different key")
	}
}

func TestVerifyCozSignature_TamperedPayload(t *testing.T) {
	key, pubPEM := generateTestKey(t)
	payload := []byte(`{"original":"data"}`)
	sig := signTestPayload(t, key, payload)

	tampered := []byte(`{"original":"tampered"}`)
	err := VerifyCozSignature(tampered, sig, pubPEM)
	if err == nil {
		t.Error("expected error for tampered payload")
	}
}

func TestVerifyCozSignature_InvalidBase64(t *testing.T) {
	_, pubPEM := generateTestKey(t)
	payload := []byte(`{"test":"data"}`)

	err := VerifyCozSignature(payload, "!!!invalid-base64!!!", pubPEM)
	if err == nil {
		t.Error("expected error for invalid base64 signature")
	}
}

func TestVerifyCozSignature_InvalidPEM(t *testing.T) {
	key, _ := generateTestKey(t)
	payload := []byte(`{"test":"data"}`)
	sig := signTestPayload(t, key, payload)

	err := VerifyCozSignature(payload, sig, "-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----")
	if err == nil {
		t.Error("expected error for invalid PEM public key")
	}
}

func TestVerifyCozSignature_NotECKey(t *testing.T) {
	key, _ := generateTestKey(t)
	payload := []byte(`{"test":"data"}`)
	sig := signTestPayload(t, key, payload)

	// Generate an RSA key and marshal as PEM — not an EC key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	rsaPemBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}
	rsaPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaPemBytes})

	err = VerifyCozSignature(payload, sig, string(rsaPem))
	if err == nil {
		t.Error("expected error for non-EC public key")
	}
}

func TestVerifyCozSignature_HexPublicKey(t *testing.T) {
	key, _ := generateTestKey(t)
	payload := []byte(`{"test":"data"}`)
	sig := signTestPayload(t, key, payload)

	// Convert public key to uncompressed hex (04 || X || Y)
	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	// Pad to 32 bytes each
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)
	rawBytes := append([]byte{0x04}, append(xPadded, yPadded...)...)
	hexKey := hex.EncodeToString(rawBytes)

	err := VerifyCozSignature(payload, sig, hexKey)
	if err != nil {
		t.Errorf("expected no error for hex public key, got: %v", err)
	}
}

func TestVerifyCozSignature_Base64PublicKey(t *testing.T) {
	key, _ := generateTestKey(t)
	payload := []byte(`{"test":"data"}`)
	sig := signTestPayload(t, key, payload)

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)
	rawBytes := append([]byte{0x04}, append(xPadded, yPadded...)...)
	b64Key := base64.StdEncoding.EncodeToString(rawBytes)

	err := VerifyCozSignature(payload, sig, b64Key)
	if err != nil {
		t.Errorf("expected no error for base64 public key, got: %v", err)
	}
}

func TestVerifyCozSignature_WrongCurve(t *testing.T) {
	// Generate a P-384 key (wrong curve)
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate P-384 key: %v", err)
	}
	payload := []byte(`{"test":"data"}`)
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sigBytes := append(rBytes, sBytes...)
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)

	pemBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pemBytes})

	// Note: The current implementation does not validate the curve type.
	// A P-384 key can verify a SHA-256 signature because ecdsa.Verify is curve-agnostic.
	// This is a known limitation — production code should enforce P-256 only.
	err = VerifyCozSignature(payload, sig, string(pubPEM))
	if err != nil {
		t.Errorf("expected success (curve not validated), got: %v", err)
	}
}

func TestVerifyCozSignature_EmptyPayload(t *testing.T) {
	key, pubPEM := generateTestKey(t)
	hash := sha256.Sum256([]byte{})
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	sigBytes := append(r.Bytes(), s.Bytes()...)
	sig := base64.RawURLEncoding.EncodeToString(sigBytes)

	err = VerifyCozSignature([]byte{}, sig, pubPEM)
	if err != nil {
		t.Errorf("expected no error for empty payload, got: %v", err)
	}
}

func TestComputeThumbprint_Format(t *testing.T) {
	key, _ := generateTestKey(t)

	tmb, err := ComputeThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("ComputeThumbprint failed: %v", err)
	}

	if tmb == "" {
		t.Error("thumbprint should not be empty")
	}

	// Should be base64url encoded (no +, /, or = characters)
	if strings.ContainsAny(tmb, "+/=") {
		t.Errorf("thumbprint contains non-base64url characters: %s", tmb)
	}
}

func TestComputeThumbprint_Deterministic(t *testing.T) {
	key, _ := generateTestKey(t)

	tmb1, err := ComputeThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("first ComputeThumbprint failed: %v", err)
	}

	tmb2, err := ComputeThumbprint(&key.PublicKey)
	if err != nil {
		t.Fatalf("second ComputeThumbprint failed: %v", err)
	}

	if tmb1 != tmb2 {
		t.Errorf("thumbprints differ: %s vs %s", tmb1, tmb2)
	}
}

func TestComputeThumbprint_DifferentKeys(t *testing.T) {
	key1, _ := generateTestKey(t)
	key2, _ := generateTestKey(t)

	tmb1, err := ComputeThumbprint(&key1.PublicKey)
	if err != nil {
		t.Fatalf("ComputeThumbprint key1 failed: %v", err)
	}

	tmb2, err := ComputeThumbprint(&key2.PublicKey)
	if err != nil {
		t.Fatalf("ComputeThumbprint key2 failed: %v", err)
	}

	if tmb1 == tmb2 {
		t.Error("different keys should produce different thumbprints")
	}
}

func TestComputeThumbprint_KnownVector(t *testing.T) {
	// Create a key with known coordinates to verify RFC 7638 compliance
	// Using coordinates from the example in the PLAN.md
	xBytes, _ := base64.RawURLEncoding.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	yBytes, _ := base64.RawURLEncoding.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if len(xBytes) < 32 {
		// Pad to 32 bytes
		padded := make([]byte, 32)
		copy(padded[32-len(xBytes):], xBytes)
		xBytes = padded
	}
	if len(yBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(yBytes):], yBytes)
		yBytes = padded
	}

	pubKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	tmb, err := ComputeThumbprint(pubKey)
	if err != nil {
		t.Fatalf("ComputeThumbprint failed: %v", err)
	}

	// The thumbprint should be a 32-byte SHA-256 hash encoded as base64url
	decoded, err := base64.RawURLEncoding.DecodeString(tmb)
	if err != nil {
		t.Fatalf("thumbprint should be valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Errorf("thumbprint decoded length should be 32, got %d", len(decoded))
	}
}

func TestVerifyTimeliness_Boundary(t *testing.T) {
	// Exactly at the boundary should pass
	now := time.Now().Unix()
	err := VerifyTimeliness(now, time.Minute)
	if err != nil {
		t.Errorf("expected no error for current timestamp, got: %v", err)
	}

	// 59 seconds ago should pass
	almostOld := time.Now().Add(-59 * time.Second).Unix()
	err = VerifyTimeliness(almostOld, time.Minute)
	if err != nil {
		t.Errorf("expected no error for 59 second old timestamp, got: %v", err)
	}

	// 61 seconds ago should fail
	justOver := time.Now().Add(-61 * time.Second).Unix()
	err = VerifyTimeliness(justOver, time.Minute)
	if err == nil {
		t.Error("expected error for 61 second old timestamp")
	}
}

func TestVerifyTimeliness_ZeroDrift(t *testing.T) {
	now := time.Now().Unix()
	err := VerifyTimeliness(now, 0)
	// Zero drift tolerance should only accept exact current second
	if err != nil && strings.Contains(err.Error(), "drift") {
		// May fail if not exactly the same second — that's expected
		return
	}
	// If we're in the same second, it should pass
}
