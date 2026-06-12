package prover

import (
	"math/big"
	"strings"
	"testing"
)

func TestDestinationHashCircuitV1AcceptsValidWitness(t *testing.T) {
	input, err := BuildDestinationHashCircuitV1Input("cosmos1alice")
	if err != nil {
		t.Fatalf("build destination hash circuit input: %v", err)
	}

	proof, err := ProveDestinationHashCircuitV1(input)
	if err != nil {
		t.Fatalf("prove destination hash circuit v1: %v", err)
	}

	if !strings.HasPrefix(proof, "0x") {
		t.Fatalf("expected 0x-prefixed proof, got %q", proof)
	}

	if len(proof) <= 2 {
		t.Fatalf("expected non-empty proof")
	}
}

func TestDestinationHashCircuitV1RejectsTamperedDestinationHash(t *testing.T) {
	input, err := BuildDestinationHashCircuitV1Input("cosmos1alice")
	if err != nil {
		t.Fatalf("build destination hash circuit input: %v", err)
	}

	input.ExpectedDestinationHash = big.NewInt(12345)

	_, err = ProveDestinationHashCircuitV1(input)
	if err == nil {
		t.Fatalf("expected tampered destination hash to fail")
	}
}

func TestDestinationHashCircuitV1IsDeterministicAtHelperLevel(t *testing.T) {
	first, err := DestinationHashCircuitV1Hex("cosmos1alice")
	if err != nil {
		t.Fatalf("derive first circuit destination hash: %v", err)
	}

	second, err := DestinationHashCircuitV1Hex(" cosmos1alice ")
	if err != nil {
		t.Fatalf("derive second circuit destination hash: %v", err)
	}

	if first != second {
		t.Fatalf("expected destination trim canonicalization, got %q and %q", first, second)
	}

	if !strings.HasPrefix(first, "0x") {
		t.Fatalf("expected 0x-prefixed destination hash, got %q", first)
	}
}

func TestDestinationHashCircuitV1DiffersFromTransitionalServiceLevelV1(t *testing.T) {
	serviceV1, err := DestinationHashForV1("cosmos1alice")
	if err != nil {
		t.Fatalf("derive service-level v1 destination hash: %v", err)
	}

	circuitV1, err := DestinationHashCircuitV1Hex("cosmos1alice")
	if err != nil {
		t.Fatalf("derive circuit v1 destination hash: %v", err)
	}

	if serviceV1 == circuitV1 {
		t.Fatalf("expected circuit field-native v1 destination hash to differ from transitional service-level v1 helper")
	}
}

func TestDestinationFieldForV1RejectsEmptyDestination(t *testing.T) {
	_, err := DestinationFieldForV1("")
	if err == nil {
		t.Fatalf("expected empty destination to fail")
	}
}
