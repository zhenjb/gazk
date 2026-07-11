package prover

import (
	"math/big"
	"testing"
)

const (
	// zk_trade_io.md §8 published vector (alice buy ATOM/USDC).
	exampleOrderHash      = "0x60ab102de75186520e5bc75fee0b76583567323946d50dddafcd0b55334dbb8a"
	exampleOrderNullifier = "0xeb02fbee136b33065013a41019599dd6390423e59721cfc7f8c05acd60466ca7"
)

// DoD anchor: the v0 wire nullifier must match the published §8 value BYTE-EXACT,
// so circuit-side gazk, off-chain P3 (state.OrderNullifierFor), and chain
// (ONCHAIN-T02) all agree on the same value for the sample order.
func TestOrderNullifierV0MatchesPublishedVector(t *testing.T) {
	got, err := OrderNullifierV0("alice", exampleOrderHash)
	if err != nil {
		t.Fatalf("OrderNullifierV0: %v", err)
	}
	if got != exampleOrderNullifier {
		t.Fatalf("v0 nullifier = %s, want %s (3-party derivation drift!)", got, exampleOrderNullifier)
	}
	if OrderNullifierDomainTagV0 != "zkdex/orderNullifier/v0" {
		t.Fatalf("domain tag drift: %q", OrderNullifierDomainTagV0)
	}
}

// Changing owner or orderHash must change the v0 nullifier (owner-binding + the
// pitfall: swapped concat order would collide).
func TestOrderNullifierV0BindsOwnerAndHash(t *testing.T) {
	base, _ := OrderNullifierV0("alice", exampleOrderHash)

	otherOwner, _ := OrderNullifierV0("bob", exampleOrderHash)
	if base == otherOwner {
		t.Fatal("v0 nullifier must depend on owner")
	}

	otherHash, _ := OrderNullifierV0("alice", "0xdeadbeef")
	if base == otherHash {
		t.Fatal("v0 nullifier must depend on orderHash")
	}

	// owner||hash order matters: N("ab","c") != N("a","bc").
	ab, _ := OrderNullifierV0("ab", "0x0c")
	a, _ := OrderNullifierV0("a", "0x0bc")
	if ab == a {
		t.Fatal("concat separators must prevent boundary collision")
	}
}

func TestOrderNullifierV0RejectsEmpty(t *testing.T) {
	if _, err := OrderNullifierV0("", exampleOrderHash); err == nil {
		t.Fatal("expected empty owner to fail")
	}
	if _, err := OrderNullifierV0("alice", ""); err == nil {
		t.Fatal("expected empty orderHash to fail")
	}
}

// In-circuit per-op template: a correctly derived field-native nullifier proves.
func TestOrderNullifierCircuitV1AcceptsValid(t *testing.T) {
	input, err := BuildOrderNullifierCircuitV1Input("alice", exampleOrderHash)
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	proof, err := ProveOrderNullifierCircuitV1(input)
	if err != nil {
		t.Fatalf("prove valid nullifier: %v", err)
	}
	if len(proof) <= 2 {
		t.Fatalf("expected non-empty proof")
	}
}

// Forged nullifier -> prove fails.
func TestOrderNullifierCircuitV1RejectsForged(t *testing.T) {
	input, err := BuildOrderNullifierCircuitV1Input("alice", exampleOrderHash)
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	input.ExpectedOrderNullifier = big.NewInt(123456789)
	if _, err := ProveOrderNullifierCircuitV1(input); err == nil {
		t.Fatal("expected forged nullifier to fail proving")
	}
}

// Wrong owner (bob) against alice's expected nullifier -> prove fails.
func TestOrderNullifierCircuitV1RejectsWrongOwner(t *testing.T) {
	alice, err := BuildOrderNullifierCircuitV1Input("alice", exampleOrderHash)
	if err != nil {
		t.Fatalf("build alice: %v", err)
	}
	bobField, err := OrderOwnerFieldForV1("bob")
	if err != nil {
		t.Fatalf("bob field: %v", err)
	}
	forged := alice
	forged.OwnerField = bobField // keep alice's expected nullifier
	if _, err := ProveOrderNullifierCircuitV1(forged); err == nil {
		t.Fatal("expected wrong owner to fail proving")
	}
}

// The in-circuit v1 nullifier differs from the v0 wire nullifier (migration gap,
// zk_trade_io.md §10) — they reconcile only at the lockstep v0->v1 bump.
func TestOrderNullifierV1DiffersFromV0(t *testing.T) {
	v1, err := OrderNullifierV1FromHashHex("alice", exampleOrderHash)
	if err != nil {
		t.Fatalf("v1 nullifier: %v", err)
	}
	if v1 == exampleOrderNullifier {
		t.Fatal("field-native v1 nullifier must differ from v0 SHA-256 nullifier")
	}
}
