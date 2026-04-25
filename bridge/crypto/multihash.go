package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

// MultihashDigest represents a multihash-encoded digest.
// Format: <hash-function-byte><length><digest>
type MultihashDigest struct {
	Function byte
	Length   int
	Digest   []byte
}

// EncodeMultihash creates a multihash from raw bytes using SHA-256.
func EncodeMultihash(data []byte) MultihashDigest {
	hash := sha256.Sum256(data)
	return MultihashDigest{
		Function: 0x12, // SHA-256
		Length:   32,
		Digest:   hash[:],
	}
}

// EncodeHex returns the hex representation of the multihash.
func (m MultihashDigest) EncodeHex() string {
	result := []byte{m.Function, byte(m.Length)}
	result = append(result, m.Digest...)
	return hex.EncodeToString(result)
}

// EncodeBase64 returns the base64url representation of the multihash.
func (m MultihashDigest) EncodeBase64() string {
	result := []byte{m.Function, byte(m.Length)}
	result = append(result, m.Digest...)
	return base64.RawURLEncoding.EncodeToString(result)
}

// ParseMultihash parses a hex-encoded multihash string.
func ParseMultihash(encoded string) (*MultihashDigest, error) {
	var data []byte
	var err error

	if len(encoded) == 0 {
		return nil, fmt.Errorf("empty multihash")
	}

	if len(encoded)%2 == 0 {
		data, err = hex.DecodeString(encoded)
	} else {
		data, err = base64.RawURLEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid multihash encoding: %w", err)
	}

	if len(data) < 2 {
		return nil, fmt.Errorf("multihash too short")
	}

	fn := data[0]
	length := int(data[1])

	if len(data) != 2+length {
		return nil, fmt.Errorf("multihash length mismatch: expected %d, got %d", length, len(data)-2)
	}

	return &MultihashDigest{
		Function: fn,
		Length:   length,
		Digest:   data[2:],
	}, nil
}

// Equal compares two multihash digests.
func (m *MultihashDigest) Equal(other *MultihashDigest) bool {
	if m.Function != other.Function || m.Length != other.Length {
		return false
	}
	if len(m.Digest) != len(other.Digest) {
		return false
	}
	for i := range m.Digest {
		if m.Digest[i] != other.Digest[i] {
			return false
		}
	}
	return true
}
