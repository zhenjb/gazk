package prover

import (
	"strings"
	"testing"
)

func TestNullifierForV1IsDeterministic(t *testing.T) {
	first, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive first nullifier v1: %v", err)
	}

	second, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive second nullifier v1: %v", err)
	}

	if first != second {
		t.Fatalf("expected deterministic nullifier v1, got %q and %q", first, second)
	}

	if !strings.HasPrefix(first, "0x") {
		t.Fatalf("expected 0x-prefixed nullifier v1, got %q", first)
	}

	if len(first) <= 2 {
		t.Fatalf("expected non-empty nullifier v1 hex, got %q", first)
	}
}

func TestNullifierForV1CanonicalizesNonce(t *testing.T) {
	one, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive nonce 1 nullifier v1: %v", err)
	}

	leadingZero, err := NullifierForV1("mock-user-secret", "01")
	if err != nil {
		t.Fatalf("derive nonce 01 nullifier v1: %v", err)
	}

	if one != leadingZero {
		t.Fatalf("expected nonce canonicalization, got %q and %q", one, leadingZero)
	}
}

func TestNullifierForV1DiffersFromV0(t *testing.T) {
	v0, err := NullifierFor("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive nullifier v0: %v", err)
	}

	v1, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive nullifier v1: %v", err)
	}

	if v0 == v1 {
		t.Fatalf("expected v1 MiMC nullifier to differ from v0 SHA-256 nullifier")
	}
}

func TestDestinationHashForV1IsDeterministic(t *testing.T) {
	first, err := DestinationHashForV1("cosmos1alice")
	if err != nil {
		t.Fatalf("derive first destination hash v1: %v", err)
	}

	second, err := DestinationHashForV1(" cosmos1alice ")
	if err != nil {
		t.Fatalf("derive second destination hash v1: %v", err)
	}

	if first != second {
		t.Fatalf("expected canonical destination trim, got %q and %q", first, second)
	}

	if !strings.HasPrefix(first, "0x") {
		t.Fatalf("expected 0x-prefixed destination hash v1, got %q", first)
	}

	if len(first) <= 2 {
		t.Fatalf("expected non-empty destination hash v1 hex, got %q", first)
	}
}

func TestDestinationHashForV1DiffersFromV0(t *testing.T) {
	v0, err := DestinationHashFor("cosmos1alice")
	if err != nil {
		t.Fatalf("derive destination hash v0: %v", err)
	}

	v1, err := DestinationHashForV1("cosmos1alice")
	if err != nil {
		t.Fatalf("derive destination hash v1: %v", err)
	}

	if v0 == v1 {
		t.Fatalf("expected v1 MiMC destination hash to differ from v0 SHA-256 destination hash")
	}
}

func TestHashV1RejectsInvalidInputs(t *testing.T) {
	if _, err := NullifierForV1("", "1"); err == nil {
		t.Fatalf("expected empty userSecret to fail")
	}

	if _, err := NullifierForV1("mock-user-secret", "-1"); err == nil {
		t.Fatalf("expected negative nonce to fail")
	}

	if _, err := NullifierForV1("mock-user-secret", "abc"); err == nil {
		t.Fatalf("expected non-numeric nonce to fail")
	}

	if _, err := DestinationHashForV1(""); err == nil {
		t.Fatalf("expected empty destination to fail")
	}
}
