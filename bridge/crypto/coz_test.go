package crypto

import (
	"testing"
	"time"
)

func TestVerifyTimeliness_Valid(t *testing.T) {
	now := time.Now().Unix()
	err := VerifyTimeliness(now, time.Minute)
	if err != nil {
		t.Errorf("expected no error for current timestamp, got: %v", err)
	}
}

func TestVerifyTimeliness_Old(t *testing.T) {
	old := time.Now().Add(-2 * time.Minute).Unix()
	err := VerifyTimeliness(old, time.Minute)
	if err == nil {
		t.Error("expected error for old timestamp")
	}
}

func TestVerifyTimeliness_Future(t *testing.T) {
	future := time.Now().Add(2 * time.Minute).Unix()
	err := VerifyTimeliness(future, time.Minute)
	if err == nil {
		t.Error("expected error for future timestamp")
	}
}
