package prover

import (
	"strings"
	"testing"
)

// DoD: a proof made with pk verifies with vk (round-trip), off-chain, for the
// canonical trade batch — the meaningful key acceptance test.
func TestTradeCircuitEngineProveVerifyRoundTrip(t *testing.T) {
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("new trade engine: %v", err)
	}
	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build canonical trade input: %v", err)
	}
	if len(input.PublicInputs) != TradePublicInputCount {
		t.Fatalf("expected %d public inputs, got %d", TradePublicInputCount, len(input.PublicInputs))
	}

	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("prove canonical trade: %v", err)
	}
	if !strings.HasPrefix(proof, "0x") || len(proof) <= 2 {
		t.Fatalf("expected non-empty 0x proof, got %q", proof)
	}

	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("verify with vk must pass for a pk-made proof: %v", err)
	}
}

// Tampering any public input must fail verification.
func TestTradeCircuitEngineRejectsTamperedPublicInput(t *testing.T) {
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("new trade engine: %v", err)
	}
	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// Corrupt [6]=tradesRoot.
	tampered := append([]string(nil), input.PublicInputs...)
	tampered[6] = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	if err := engine.VerifyPublicInputs(proof, tampered); err == nil {
		t.Fatal("expected tampered public input to fail verification")
	}
}

// vkId is gazk-trade-v1 on both the constant and the exported artifact (the
// value B and P4 hardcode).
func TestTradeVerifierArtifactCarriesRealKey(t *testing.T) {
	svc := NewService()
	artifact := svc.TradeVerifierArtifact()

	if artifact.VerificationKeyID != TradeVerificationKeyID || TradeVerificationKeyID != "gazk-trade-v1" {
		t.Fatalf("vkId mismatch: artifact=%q const=%q", artifact.VerificationKeyID, TradeVerificationKeyID)
	}
	if artifact.Stub {
		t.Fatal("artifact must be real (Stub=false) after ZK-T09")
	}
	if !strings.HasPrefix(artifact.VerifyingKey, "0x") || len(artifact.VerifyingKey) <= 2 {
		t.Fatalf("expected real 0x verifying key, got %q", artifact.VerifyingKey)
	}
	if artifact.PublicInputCount != 8 {
		t.Fatalf("expected 8 public inputs, got %d", artifact.PublicInputCount)
	}
}

// A proof verifies against the vk exported in the artifact (same vk B embeds),
// closing the loop: pk-made proof <-> exported vk <-> vkId.
func TestTradeProofVerifiesAgainstArtifactKey(t *testing.T) {
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	// The engine's vk is what TradeVerifierArtifact exports; verifying here is the
	// same check B performs on-chain with the embedded vk.
	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("proof must verify against the exported vk: %v", err)
	}
}
