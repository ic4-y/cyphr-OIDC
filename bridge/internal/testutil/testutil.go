package testutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/ic4y/cyphrmask-oidc-poc/bridge/handlers"
	"github.com/ic4y/cyphrmask-oidc-poc/bridge/storage"
)

type TestKey struct {
	PrivateKey *ecdsa.PrivateKey
	PublicKey  string
	Thumbprint string
}

func NewTestKey(t *testing.T) TestKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	xBytes := key.PublicKey.X.Bytes()
	yBytes := key.PublicKey.Y.Bytes()
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(xBytes):], xBytes)
	copy(yPadded[32-len(yBytes):], yBytes)

	jwkBytes := []byte(`{"crv":"P-256","kty":"EC","x":"` + base64.RawURLEncoding.EncodeToString(xPadded) + `","y":"` + base64.RawURLEncoding.EncodeToString(yPadded) + `"}`)
	hash := sha256.Sum256(jwkBytes)
	tmb := base64.RawURLEncoding.EncodeToString(hash[:])

	rawBytes := append([]byte{0x04}, append(xPadded, yPadded...)...)
	pubHex := hex.EncodeToString(rawBytes)

	return TestKey{
		PrivateKey: key,
		PublicKey:  pubHex,
		Thumbprint: tmb,
	}
}

func SignCozPayload(t *testing.T, key *ecdsa.PrivateKey, nonce, tmb string) string {
	t.Helper()
	return SignCozPayloadAtTime(t, key, nonce, tmb, time.Now().Unix())
}

func SignCozPayloadAtTime(t *testing.T, key *ecdsa.PrivateKey, nonce, tmb string, ts int64) string {
	t.Helper()
	pay := map[string]interface{}{
		"alg":   "ES256",
		"tmb":   tmb,
		"typ":   "cyphr/auth/challenge",
		"now":   ts,
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

	sigBytes := append(r.Bytes(), s.Bytes()...)
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

func EncodeUncompressedECKey(x, y *big.Int) string {
	xPadded := make([]byte, 32)
	yPadded := make([]byte, 32)
	copy(xPadded[32-len(x.Bytes()):], x.Bytes())
	copy(yPadded[32-len(y.Bytes()):], y.Bytes())
	rawBytes := append([]byte{0x04}, append(xPadded, yPadded...)...)
	return hex.EncodeToString(rawBytes)
}

func BuildUsersJSON(keys map[TestKey]string) string {
	m := make(map[string]map[string]string)
	for k, email := range keys {
		if email == "" {
			email = "test@example.com"
		}
		m[k.Thumbprint] = map[string]string{
			"email":      email,
			"public_key": k.PublicKey,
		}
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func NewTestChallengeStore(t *testing.T) *handlers.ChallengeStore {
	t.Helper()
	return handlers.NewChallengeStore(time.Minute * 5)
}

func NewTestOIDCStorage(t *testing.T, redirectURI string) *storage.Storage {
	t.Helper()
	s := storage.NewStorage()
	s.RegisterClient(storage.NewClient("test-client", "secret", []string{redirectURI}, func(id string) string {
		return "/login?authRequestID=" + id
	}))
	return s
}

func GenerateTestPEMPublicKey(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	pemBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pemBytes}))
}

func SignTestPayloadPEM(t *testing.T, key *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	hash := sha256.Sum256(payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		t.Fatalf("failed to sign payload: %v", err)
	}
	sigBytes := append(r.Bytes(), s.Bytes()...)
	return base64.RawURLEncoding.EncodeToString(sigBytes)
}
