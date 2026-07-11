package prover

import (
	"testing"
)

// A mixed batch touching all three op types in one root transition:
//   - dave  (deposit-only):   +1000 uusdc
//   - wendy (withdraw-only):  -300 uusdc
//   - alice (trade buyer):    -2010 uusdc quote out (buyerQuoteOut)
//   - bob   (trade seller):   +1980 uusdc quote in  (sellerQuoteIn)
func mixedBatchCells() []StateCell {
	return []StateCell{
		{Owner: "dave", Denom: "uusdc", OldBalance: "0", DeltaIn: "1000", DeltaOut: "0"},
		{Owner: "wendy", Denom: "uusdc", OldBalance: "500", DeltaIn: "0", DeltaOut: "300"},
		{Owner: "alice", Denom: "uusdc", OldBalance: "2010", DeltaIn: "0", DeltaOut: "2010"},
		{Owner: "bob", Denom: "uusdc", OldBalance: "0", DeltaIn: "1980", DeltaOut: "0"},
	}
}

func TestUnifiedRootTransitionAcceptsMixedBatch(t *testing.T) {
	input, err := BuildUnifiedRootTransitionCircuitV1Input(mixedBatchCells())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	if input.OldStateRoot == input.NewStateRoot {
		t.Fatal("old and new state roots must differ for a non-trivial batch")
	}
	proof, err := ProveUnifiedRootTransitionCircuitV1(input)
	if err != nil {
		t.Fatalf("prove mixed batch: %v", err)
	}
	if len(proof) <= 2 {
		t.Fatal("expected non-empty proof")
	}
}

// Deposit/withdraw-only batch (trade cells zero) must also transition correctly.
func TestUnifiedRootTransitionAcceptsNoTradeBatch(t *testing.T) {
	cells := []StateCell{
		{Owner: "dave", Denom: "uusdc", OldBalance: "0", DeltaIn: "1000", DeltaOut: "0"},
		{Owner: "wendy", Denom: "uusdc", OldBalance: "500", DeltaIn: "0", DeltaOut: "300"},
	}
	input, err := BuildUnifiedRootTransitionCircuitV1Input(cells)
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	if _, err := ProveUnifiedRootTransitionCircuitV1(input); err != nil {
		t.Fatalf("prove no-trade batch: %v", err)
	}
}

// Changing a balance while keeping the public root -> new-root fold mismatch -> fail.
func TestUnifiedRootTransitionRejectsTamperedBalance(t *testing.T) {
	input, err := BuildUnifiedRootTransitionCircuitV1Input(mixedBatchCells())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	input.TamperCellBalance(3, 999999) // bob should be 1980
	if _, err := ProveUnifiedRootTransitionCircuitV1(input); err == nil {
		t.Fatal("expected tampered new balance to fail the transition")
	}
}

// Forging the public newStateRoot -> fold mismatch -> fail.
func TestUnifiedRootTransitionRejectsTamperedRoot(t *testing.T) {
	input, err := BuildUnifiedRootTransitionCircuitV1Input(mixedBatchCells())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	input.TamperNewStateRoot()
	if _, err := ProveUnifiedRootTransitionCircuitV1(input); err == nil {
		t.Fatal("expected tampered newStateRoot to fail")
	}
}

// A cell driven negative (withdraw more than held) is rejected at build.
func TestUnifiedRootTransitionRejectsNegativeBalance(t *testing.T) {
	cells := []StateCell{
		{Owner: "wendy", Denom: "uusdc", OldBalance: "100", DeltaIn: "0", DeltaOut: "300"},
	}
	if _, err := BuildUnifiedRootTransitionCircuitV1Input(cells); err == nil {
		t.Fatal("expected negative newBalance to be rejected at build")
	}
}

func TestUnifiedRootTransitionRejectsTooManyCells(t *testing.T) {
	cells := make([]StateCell, maxStateCells+1)
	for i := range cells {
		cells[i] = StateCell{Owner: "x", Denom: "uusdc", OldBalance: "0", DeltaIn: "0", DeltaOut: "0"}
	}
	if _, err := BuildUnifiedRootTransitionCircuitV1Input(cells); err == nil {
		t.Fatal("expected too many cells to be rejected")
	}
}

// Padding is deterministic: the same logical batch yields the same roots.
func TestUnifiedRootTransitionDeterministic(t *testing.T) {
	a, err := BuildUnifiedRootTransitionCircuitV1Input(mixedBatchCells())
	if err != nil {
		t.Fatalf("build a: %v", err)
	}
	b, err := BuildUnifiedRootTransitionCircuitV1Input(mixedBatchCells())
	if err != nil {
		t.Fatalf("build b: %v", err)
	}
	if a.OldStateRoot != b.OldStateRoot || a.NewStateRoot != b.NewStateRoot {
		t.Fatal("roots must be deterministic")
	}
}
