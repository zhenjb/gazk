package prover

import (
	"math/big"
	"strings"
	"testing"
)

func TestAccountCommitmentCircuitV1AcceptsValidWitness(t *testing.T) {
	input, err := BuildAccountCommitmentCircuitV1Input(
		"cosmos1alice",
		"0",
		"100",
		"40",
		"60",
	)
	if err != nil {
		t.Fatalf("build account commitment circuit input: %v", err)
	}

	proof, err := ProveAccountCommitmentCircuitV1(input)
	if err != nil {
		t.Fatalf("prove account commitment circuit v1: %v", err)
	}

	if !strings.HasPrefix(proof, "0x") {
		t.Fatalf("expected 0x-prefixed proof, got %q", proof)
	}

	if len(proof) <= 2 {
		t.Fatalf("expected non-empty proof")
	}
}

func TestAccountCommitmentCircuitV1RejectsTamperedOldCommitment(t *testing.T) {
	input, err := BuildAccountCommitmentCircuitV1Input(
		"cosmos1alice",
		"0",
		"100",
		"40",
		"60",
	)
	if err != nil {
		t.Fatalf("build account commitment circuit input: %v", err)
	}

	input.OldAccountCommitment = big.NewInt(12345)

	_, err = ProveAccountCommitmentCircuitV1(input)
	if err == nil {
		t.Fatalf("expected tampered old account commitment to fail")
	}
}

func TestAccountCommitmentCircuitV1RejectsTamperedNewCommitment(t *testing.T) {
	input, err := BuildAccountCommitmentCircuitV1Input(
		"cosmos1alice",
		"0",
		"100",
		"40",
		"60",
	)
	if err != nil {
		t.Fatalf("build account commitment circuit input: %v", err)
	}

	input.NewAccountCommitment = big.NewInt(12345)

	_, err = ProveAccountCommitmentCircuitV1(input)
	if err == nil {
		t.Fatalf("expected tampered new account commitment to fail")
	}
}

func TestAccountCommitmentCircuitV1RejectsInvalidBalanceTransition(t *testing.T) {
	_, err := BuildAccountCommitmentCircuitV1Input(
		"cosmos1alice",
		"0",
		"100",
		"40",
		"70",
	)
	if err == nil {
		t.Fatalf("expected invalid balance transition to fail")
	}
}

func TestAccountCommitmentCircuitV1IsDeterministicAtHelperLevel(t *testing.T) {
	first, err := AccountCommitmentCircuitV1Hex("cosmos1alice", "60")
	if err != nil {
		t.Fatalf("derive first account commitment: %v", err)
	}

	second, err := AccountCommitmentCircuitV1Hex(" cosmos1alice ", "60")
	if err != nil {
		t.Fatalf("derive second account commitment: %v", err)
	}

	if first != second {
		t.Fatalf("expected owner trim canonicalization, got %q and %q", first, second)
	}

	if !strings.HasPrefix(first, "0x") {
		t.Fatalf("expected 0x-prefixed account commitment, got %q", first)
	}
}

func TestAccountCommitmentCircuitV1CommitmentChangesWithBalance(t *testing.T) {
	oldCommitment, err := AccountCommitmentCircuitV1Hex("cosmos1alice", "0")
	if err != nil {
		t.Fatalf("derive old account commitment: %v", err)
	}

	newCommitment, err := AccountCommitmentCircuitV1Hex("cosmos1alice", "60")
	if err != nil {
		t.Fatalf("derive new account commitment: %v", err)
	}

	if oldCommitment == newCommitment {
		t.Fatalf("expected commitment to change when balance changes")
	}
}

func TestOwnerFieldForV1RejectsEmptyOwner(t *testing.T) {
	_, err := OwnerFieldForV1("")
	if err == nil {
		t.Fatalf("expected empty owner to fail")
	}
}
