package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// VerifyCozSignature verifies the Coz signature against the payload bytes.
// Supports ES256 (P-256 ECDSA) as specified in the PLAN.md.
func VerifyCozSignature(payBytes []byte, sigBase64 string, pubKeyPEM string) error {
	hash := sha256.Sum256(payBytes)

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigBase64)
	if err != nil {
		sigBytes, err = base64.StdEncoding.DecodeString(sigBase64)
		if err != nil {
			return fmt.Errorf("invalid base64 signature: %w", err)
		}
	}

	pubKey, err := parsePublicKey(pubKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	r := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
	s := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])

	if !ecdsa.Verify(pubKey, hash[:], r, s) {
		return fmt.Errorf("Coz signature verification failed")
	}

	return nil
}

// VerifyTimeliness checks that the Coz timestamp is within the allowed window.
func VerifyTimeliness(now int64, maxDrift time.Duration) error {
	serverTime := time.Now().Unix()
	diff := now - serverTime
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(maxDrift.Seconds()) {
		return fmt.Errorf("Coz timestamp drift: %d seconds (max %d)", diff, int64(maxDrift.Seconds()))
	}
	return nil
}

// ComputeThumbprint computes the thumbprint (tmb) for a public key.
// Uses base64url-encoded SHA-256 of the JWK representation.
func ComputeThumbprint(pubKey *ecdsa.PublicKey) (string, error) {
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   encodeBigInt(pubKey.X),
		"y":   encodeBigInt(pubKey.Y),
	}
	jwkBytes, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(jwkBytes)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

func parsePublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	pemStr = strings.TrimSpace(pemStr)

	if strings.HasPrefix(pemStr, "-----BEGIN") {
		return parsePEMPublicKey(pemStr)
	}

	return parseRawPublicKey(pemStr)
}

func parsePEMPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an EC public key")
	}
	return ecPub, nil
}

func parseRawPublicKey(raw string) (*ecdsa.PublicKey, error) {
	bytes, err := hex.DecodeString(raw)
	if err != nil {
		bytes, err = base64.StdEncoding.DecodeString(raw)
		if err != nil {
			bytes, err = base64.RawURLEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid public key encoding")
			}
		}
	}

	if len(bytes) != 65 {
		return nil, fmt.Errorf("invalid uncompressed EC key length: %d", len(bytes))
	}

	if bytes[0] != 0x04 {
		return nil, fmt.Errorf("invalid EC key prefix: %02x", bytes[0])
	}

	x := new(big.Int).SetBytes(bytes[1:33])
	y := new(big.Int).SetBytes(bytes[33:65])

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}, nil
}

func encodeBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}
