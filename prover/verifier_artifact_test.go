package prover

import (
	"strings"
	"testing"
)

func TestVerifierArtifactV0(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV0SHA256.String())

	artifact, err := service.VerifierArtifact()
	if err != nil {
		t.Fatalf("export v0 verifier artifact: %v", err)
	}

	if artifact.VerificationKeyID != VerificationKeyID {
		t.Fatalf("verificationKeyId: expected %q, got %q", VerificationKeyID, artifact.VerificationKeyID)
	}

	if artifact.HashMode != HashModeV0SHA256.String() {
		t.Fatalf("hashMode: expected %q, got %q", HashModeV0SHA256.String(), artifact.HashMode)
	}

	assertVerifierArtifactShape(t, artifact.VerifyingKey, artifact.PublicInputCount, artifact.PublicInputNames)
}

func TestVerifierArtifactV1(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	artifact, err := service.VerifierArtifact()
	if err != nil {
		t.Fatalf("export v1 verifier artifact: %v", err)
	}

	if artifact.VerificationKeyID != VerificationKeyIDV1 {
		t.Fatalf("verificationKeyId: expected %q, got %q", VerificationKeyIDV1, artifact.VerificationKeyID)
	}

	if artifact.HashMode != HashModeV1MiMC.String() {
		t.Fatalf("hashMode: expected %q, got %q", HashModeV1MiMC.String(), artifact.HashMode)
	}

	assertVerifierArtifactShape(t, artifact.VerifyingKey, artifact.PublicInputCount, artifact.PublicInputNames)
}

func assertVerifierArtifactShape(t *testing.T, verifyingKey string, publicInputCount int, publicInputNames []string) {
	t.Helper()

	if !strings.HasPrefix(verifyingKey, "0x") {
		t.Fatalf("expected 0x-prefixed verifying key")
	}

	if len(verifyingKey) <= 2 {
		t.Fatalf("expected non-empty verifying key")
	}

	if publicInputCount != 6 {
		t.Fatalf("expected publicInputCount=6, got %d", publicInputCount)
	}

	if len(publicInputNames) != 6 {
		t.Fatalf("expected 6 public input names, got %d", len(publicInputNames))
	}
}
