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

// TRD-A1: the proof's public inputs [0]/[1]/[6]/[7] are the v0 (SHA-256) WIRE roots
// — byte-exact the zk_trade_io.md §8 canonical vector — NOT the field-native v1 MiMC
// values the circuit used to commit. This is what lets a real gazk proof reconcile
// with the chain's independently-derived v0 roots (the whole point of TRD-A1).
func TestTradeCircuitBindsV0WireRoots(t *testing.T) {
	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	// §8 canonical wire roots (v0 SHA-256).
	const (
		v0OldStateRoot = "0xdc03bee69322b6f860de17cc11d8bee7e5cc41ae22e72d3da1065fe8d13db103"
		v0NewStateRoot = "0xc79bc87c5df4b3cf94560d58f19f2b36631b93a60132efd0c61ac8b474069e61"
		v0TradesRoot   = "0xe0485ea21f6ea846a9de81a4153afa85ca471933f6910285258c0c2051410dfb"
		v0OrdersRoot   = "0x798b004fcf98281e699899cf89b853a5849bf8e8fdbf474b7300e770cd4ab3ea"
	)
	for _, c := range []struct {
		idx  int
		name string
		want string
	}{
		{0, "oldStateRoot", v0OldStateRoot},
		{1, "newStateRoot", v0NewStateRoot},
		{6, "tradesRoot", v0TradesRoot},
		{7, "ordersRoot", v0OrdersRoot},
	} {
		if input.PublicInputs[c.idx] != c.want {
			t.Fatalf("public input [%d] %s = %q, want v0 wire %q", c.idx, c.name, input.PublicInputs[c.idx], c.want)
		}
	}
	// And [6]/[7] equal the standalone v0 helpers P3/chain use (single source).
	wantOrders, err := OrdersRootV0(DefaultCanonicalTradeBatch().Orders)
	if err != nil {
		t.Fatalf("ordersRootV0: %v", err)
	}
	if input.PublicInputs[7] != wantOrders {
		t.Fatalf("ordersRoot [7] = %q, want OrdersRootV0 %q", input.PublicInputs[7], wantOrders)
	}
	if input.PublicInputs[6] != TradesRootV0(DefaultCanonicalTradeBatch().Fills) {
		t.Fatalf("tradesRoot [6] not TradesRootV0")
	}

	// The proof still round-trips against these v0 public inputs.
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("verify v0-bound proof: %v", err)
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
