package prover

import (
	"math/big"
	"strings"
	"testing"
)

// aliceBuyOrder mirrors the canonical example order in zk_trade_io.md §8 /
// STATE-T11 (alice buy ATOM/USDC 100 x 20, expiry 2000000, nonce 1).
func aliceBuyOrder() OrderFieldsV1 {
	return OrderFieldsV1{
		Owner:  "alice",
		Market: "ATOM/USDC",
		Side:   "buy",
		Price:  "100",
		Qty:    "20",
		Expiry: "2000000",
		Nonce:  "1",
	}
}

func TestOrderHashBindingCircuitV1AcceptsValidOrder(t *testing.T) {
	input, err := BuildOrderHashBindingCircuitV1Input(aliceBuyOrder())
	if err != nil {
		t.Fatalf("build order input: %v", err)
	}

	proof, err := ProveOrderHashBindingCircuitV1(input)
	if err != nil {
		t.Fatalf("prove valid order: %v", err)
	}
	if !strings.HasPrefix(proof, "0x") || len(proof) <= 2 {
		t.Fatalf("expected non-empty 0x proof, got %q", proof)
	}

	// The valid proof must also verify against its own public commitments.
	if err := ProveAndVerifyOrderHashBindingCircuitV1(
		input, input.ExpectedOrderCommitment, input.ExpectedOrderNullifier,
	); err != nil {
		t.Fatalf("verify valid order: %v", err)
	}
}

func TestOrderHashBindingCircuitV1RejectsTamperedCommitment(t *testing.T) {
	input, err := BuildOrderHashBindingCircuitV1Input(aliceBuyOrder())
	if err != nil {
		t.Fatalf("build order input: %v", err)
	}

	// Forge the public commitment while keeping the honest fields.
	input.ExpectedOrderCommitment = big.NewInt(999999)

	if _, err := ProveOrderHashBindingCircuitV1(input); err == nil {
		t.Fatal("expected tampered orderCommitment to fail proving")
	}
}

func TestOrderHashBindingCircuitV1RejectsTamperedNullifier(t *testing.T) {
	input, err := BuildOrderHashBindingCircuitV1Input(aliceBuyOrder())
	if err != nil {
		t.Fatalf("build order input: %v", err)
	}

	input.ExpectedOrderNullifier = big.NewInt(424242)

	if _, err := ProveOrderHashBindingCircuitV1(input); err == nil {
		t.Fatal("expected tampered orderNullifier to fail proving")
	}
}

// The core security property: alice's order commitment/nullifier cannot be
// replayed under a different owner. Take alice's honest public commitments but
// swap the private OwnerField to bob's — the circuit recomputes a different
// commitment and AssertIsEqual fails.
func TestOrderHashBindingCircuitV1RejectsOwnerReplay(t *testing.T) {
	alice, err := BuildOrderHashBindingCircuitV1Input(aliceBuyOrder())
	if err != nil {
		t.Fatalf("build alice input: %v", err)
	}

	bobField, err := OrderOwnerFieldForV1("bob")
	if err != nil {
		t.Fatalf("bob owner field: %v", err)
	}

	forged := alice
	forged.OwnerField = bobField // bob tries to reuse alice's commitment/nullifier

	if _, err := ProveOrderHashBindingCircuitV1(forged); err == nil {
		t.Fatal("expected owner replay (bob reusing alice's commitment) to fail proving")
	}
}

func TestOrderHashBindingCircuitV1DeterministicAndOwnerBound(t *testing.T) {
	aliceCommit, err := OrderCommitmentCircuitV1Hex(aliceBuyOrder())
	if err != nil {
		t.Fatalf("alice commitment: %v", err)
	}
	aliceCommit2, err := OrderCommitmentCircuitV1Hex(aliceBuyOrder())
	if err != nil {
		t.Fatalf("alice commitment repeat: %v", err)
	}
	if aliceCommit != aliceCommit2 {
		t.Fatalf("commitment not deterministic: %q vs %q", aliceCommit, aliceCommit2)
	}
	if !strings.HasPrefix(aliceCommit, "0x") {
		t.Fatalf("expected 0x commitment, got %q", aliceCommit)
	}

	// Same order fields but different owner -> different commitment (owner bound).
	bobOrder := aliceBuyOrder()
	bobOrder.Owner = "bob"
	bobCommit, err := OrderCommitmentCircuitV1Hex(bobOrder)
	if err != nil {
		t.Fatalf("bob commitment: %v", err)
	}
	if aliceCommit == bobCommit {
		t.Fatal("expected owner to be bound into orderCommitment")
	}

	// Nullifier differs by owner too.
	aliceNull, err := OrderNullifierCircuitV1Hex(aliceBuyOrder())
	if err != nil {
		t.Fatalf("alice nullifier: %v", err)
	}
	bobNull, err := OrderNullifierCircuitV1Hex(bobOrder)
	if err != nil {
		t.Fatalf("bob nullifier: %v", err)
	}
	if aliceNull == bobNull {
		t.Fatal("expected owner to be bound into orderNullifier")
	}
}

// The field-native v1 order commitment must DIFFER from the v0 SHA-256 orderHash
// (zk_trade_io.md §10 migration). Here we just assert the circuit v1 commitment
// is not the published v0 orderHash of the same order.
func TestOrderHashBindingCircuitV1DiffersFromV0OrderHash(t *testing.T) {
	const v0OrderHash = "0x60ab102de75186520e5bc75fee0b76583567323946d50dddafcd0b55334dbb8a"

	v1Commit, err := OrderCommitmentCircuitV1Hex(aliceBuyOrder())
	if err != nil {
		t.Fatalf("v1 commitment: %v", err)
	}
	if v1Commit == v0OrderHash {
		t.Fatal("field-native v1 commitment must differ from v0 SHA-256 orderHash")
	}
}

func TestOrderHashBindingCircuitV1RejectsBadFields(t *testing.T) {
	cases := []OrderFieldsV1{
		{Owner: "", Market: "ATOM/USDC", Side: "buy", Price: "1", Qty: "1", Expiry: "1", Nonce: "1"},
		{Owner: "alice", Market: "ATOM/USDC", Side: "hold", Price: "1", Qty: "1", Expiry: "1", Nonce: "1"},
		{Owner: "alice", Market: "ATOM/USDC", Side: "buy", Price: "-1", Qty: "1", Expiry: "1", Nonce: "1"},
	}
	for i, order := range cases {
		if _, err := BuildOrderHashBindingCircuitV1Input(order); err == nil {
			t.Fatalf("case %d: expected invalid order to fail input build", i)
		}
	}
}
