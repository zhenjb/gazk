package prover

import (
	"path/filepath"
	"strings"
	"testing"
)

// TRD-A2: the fingerprint guard must self-heal a STALE persisted key (a key that
// does not match the current trade circuit — the silent-failure hazard after a
// circuit change). We simulate it by persisting a DIFFERENT circuit's key under the
// trade key's file names (no matching fingerprint), then asserting the engine
// REGENERATES a valid key and ends up healthy (canonical proof verifies), and a
// fingerprint sidecar now exists.
func TestTradeEngineStaleKeyIsRegenerated(t *testing.T) {
	dir := t.TempDir()
	_, pk, vk, err := compileAndSetupMultiWithdrawalCircuit() // a foreign circuit
	if err != nil {
		t.Fatalf("setup foreign circuit: %v", err)
	}
	pkPath := filepath.Join(dir, TradeVerificationKeyID+".proving.key")
	vkPath := filepath.Join(dir, TradeVerificationKeyID+".verifying.key")
	fpPath := filepath.Join(dir, TradeVerificationKeyID+".circuit.sha256")
	if err := saveGroth16Keys(pk, vk, pkPath, vkPath); err != nil {
		t.Fatalf("persist foreign key: %v", err)
	}
	if fileExists(fpPath) {
		t.Fatal("precondition: no fingerprint should exist yet")
	}

	t.Setenv(KeyDirEnv, dir)
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("engine must self-heal a stale key, got: %v", err)
	}
	if !fileExists(fpPath) {
		t.Fatal("expected a circuit fingerprint sidecar after regeneration")
	}
	// The regenerated key is healthy: the canonical proof verifies.
	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("prove with regenerated key: %v", err)
	}
	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("regenerated key must produce a verifying proof: %v", err)
	}
}

// TRD-A2: keys persist deterministically. A first engine sets up + persists +
// self-verifies; a second engine LOADS the persisted keys, self-verifies, and its
// vk verifies a proof made by the first engine's pk (same setup) — the exact vk B
// embeds on-chain.
func TestTradeEnginePersistedKeyRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(KeyDirEnv, dir)

	e1, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("first engine (setup + persist): %v", err)
	}
	if !fileExists(filepath.Join(dir, TradeVerificationKeyID+".verifying.key")) ||
		!fileExists(filepath.Join(dir, TradeVerificationKeyID+".proving.key")) {
		t.Fatal("expected pk/vk to be persisted under GAZK_KEY_DIR")
	}

	e2, err := NewTradeCircuitEngine() // loads the persisted keys (+ self-check)
	if err != nil {
		t.Fatalf("second engine (load persisted): %v", err)
	}

	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	proof, err := e1.Prove(input)
	if err != nil {
		t.Fatalf("prove with persisted pk: %v", err)
	}
	if err := e2.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("persisted vk must verify a proof from the persisted pk: %v", err)
	}
}

// TRD-A2: the exported trade verifier artifact is the real, embeddable contract for
// B — real vk hex (not a stub), vkId gazk-trade-v1, and the locked 8 public-input
// names in order. This is exactly what `gazk export-trade-verifier-artifact` writes.
func TestTradeVerifierArtifactIsEmbeddable(t *testing.T) {
	a := NewService().TradeVerifierArtifact()
	if a.Stub {
		t.Fatal("artifact must be real (Stub=false) for B to embed")
	}
	if a.VerificationKeyID != TradeVerificationKeyID {
		t.Fatalf("vkId = %q, want %q", a.VerificationKeyID, TradeVerificationKeyID)
	}
	if !strings.HasPrefix(a.VerifyingKey, "0x") || len(a.VerifyingKey) <= 2 {
		t.Fatalf("expected real vk hex, got %q", a.VerifyingKey)
	}
	if a.PublicInputCount != TradePublicInputCount || len(a.PublicInputNames) != TradePublicInputCount {
		t.Fatalf("expected %d public-input names, got count=%d len=%d", TradePublicInputCount, a.PublicInputCount, len(a.PublicInputNames))
	}
	if a.PublicInputNames[0] != "settlementUpdate.oldStateRoot" ||
		a.PublicInputNames[6] != "batchCommitments.tradesRoot" ||
		a.PublicInputNames[7] != "batchCommitments.ordersRoot" {
		t.Fatalf("locked layout drift: %v", a.PublicInputNames)
	}
}
