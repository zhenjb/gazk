package prover

import "testing"

func TestParseHashModeDefaultsToV0(t *testing.T) {
	mode, err := ParseHashMode("")
	if err != nil {
		t.Fatalf("parse empty hash mode: %v", err)
	}

	if mode != HashModeV0SHA256 {
		t.Fatalf("expected default hash mode %q, got %q", HashModeV0SHA256, mode)
	}
}

func TestParseHashModeAcceptsKnownModes(t *testing.T) {
	tests := []HashMode{
		HashModeV0SHA256,
		HashModeV1MiMC,
	}

	for _, want := range tests {
		t.Run(want.String(), func(t *testing.T) {
			got, err := ParseHashMode(want.String())
			if err != nil {
				t.Fatalf("parse hash mode: %v", err)
			}

			if got != want {
				t.Fatalf("expected %q, got %q", want, got)
			}
		})
	}
}

func TestParseHashModeRejectsUnknownMode(t *testing.T) {
	_, err := ParseHashMode("sha3")
	if err == nil {
		t.Fatalf("expected unknown hash mode to fail")
	}
}

func TestNewServiceDefaultsToV0HashMode(t *testing.T) {
	service := NewServiceWithHashMode("")

	if service.HashMode() != HashModeV0SHA256 {
		t.Fatalf("expected service hash mode %q, got %q", HashModeV0SHA256, service.HashMode())
	}
}

func TestProveRejectsUnknownHashMode(t *testing.T) {
	service := NewServiceWithHashMode("unknown-mode")

	_, err := service.Prove(validAliceProveRequest())
	if err == nil {
		t.Fatalf("expected unknown hash mode to fail")
	}
}

func TestProveV1HashModeIsEnabledButRequiresCircuitV1Hashes(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	_, err := service.Prove(validAliceProveRequest())
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject current v0 Alice vector")
	}
}

func TestProveDefaultV0StillAcceptsCurrentAliceVector(t *testing.T) {
	service := NewServiceWithHashMode("")

	_, err := service.Prove(validAliceProveRequest())
	if err != nil {
		t.Fatalf("expected default v0 prove to accept current Alice vector: %v", err)
	}
}
