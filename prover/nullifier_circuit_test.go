package prover

import (
	"math/big"
	"strings"
	"testing"
)

func TestNullifierCircuitV1AcceptsValidWitness(t *testing.T) {
	input, err := BuildNullifierCircuitV1Input("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("build nullifier circuit input: %v", err)
	}

	proof, err := ProveNullifierCircuitV1(input)
	if err != nil {
		t.Fatalf("prove nullifier circuit v1: %v", err)
	}

	if !strings.HasPrefix(proof, "0x") {
		t.Fatalf("expected 0x-prefixed proof, got %q", proof)
	}

	if len(proof) <= 2 {
		t.Fatalf("expected non-empty proof")
	}
}

func TestNullifierCircuitV1RejectsTamperedNullifier(t *testing.T) {
	input, err := BuildNullifierCircuitV1Input("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("build nullifier circuit input: %v", err)
	}

	input.ExpectedNullifier = newBigIntForTest(12345)

	_, err = ProveNullifierCircuitV1(input)
	if err == nil {
		t.Fatalf("expected tampered nullifier to fail")
	}
}

func TestNullifierCircuitV1IsDeterministicAtHelperLevel(t *testing.T) {
	first, err := NullifierCircuitV1Hex("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive first circuit nullifier: %v", err)
	}

	second, err := NullifierCircuitV1Hex("mock-user-secret", "01")
	if err != nil {
		t.Fatalf("derive second circuit nullifier: %v", err)
	}

	if first != second {
		t.Fatalf("expected nonce canonicalization, got %q and %q", first, second)
	}

	if !strings.HasPrefix(first, "0x") {
		t.Fatalf("expected 0x-prefixed nullifier, got %q", first)
	}
}

func TestNullifierCircuitV1DiffersFromServiceLevelV1(t *testing.T) {
	serviceV1, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive service-level v1 nullifier: %v", err)
	}

	circuitV1, err := NullifierCircuitV1Hex("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive circuit v1 nullifier: %v", err)
	}

	if serviceV1 == circuitV1 {
		t.Fatalf("expected circuit field-native v1 nullifier to differ from transitional service-level v1 helper")
	}
}

func TestSecretFieldForV1RejectsEmptySecret(t *testing.T) {
	_, err := SecretFieldForV1("")
	if err == nil {
		t.Fatalf("expected empty userSecret to fail")
	}
}

func newBigIntForTest(value int64) *big.Int {
	return big.NewInt(value)
}
