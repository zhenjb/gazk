package prover

import (
	"testing"
)

const (
	exampleOrdersRoot = "0x798b004fcf98281e699899cf89b853a5849bf8e8fdbf474b7300e770cd4ab3ea"
	exampleTradesRoot = "0xe0485ea21f6ea846a9de81a4153afa85ca471933f6910285258c0c2051410dfb"

	bobOrderHash = "0xbeeae7ff0bad0b8e19594892537e52e77a17cfd0b6c92ebfe105911c1897749f"
	exampleTrade = "0xc0b11f3a4fbf7ca3ba85c2b90a7c4c6337da9001e14dd2b5bf0d149a8c06cd14"
)

// The alice/bob canonical batch (zk_trade_io.md §8 / STATE-T11).
func aliceBobOrders() []OrderLeaf {
	return []OrderLeaf{
		{OrderHash: exampleOrderHash, Owner: "alice", Side: "buy", Price: "100", Qty: "20", Remaining: "0", Filled: true, Sequence: 1},
		{OrderHash: bobOrderHash, Owner: "bob", Side: "sell", Price: "100", Qty: "20", Remaining: "0", Filled: true, Sequence: 2},
	}
}

func aliceBobFills() []FillLeaf {
	return []FillLeaf{{
		TradeID: exampleTrade, Market: "ATOM/USDC",
		MakerOrderHash: exampleOrderHash, TakerOrderHash: bobOrderHash,
		Price: "100", Qty: "20", MakerFee: "10", TakerFee: "20", Buyer: "alice", Seller: "bob",
	}}
}

// DoD / cross-party anchor: gazk v0 roots must match the published §8 vector
// BYTE-EXACT (== P3 BuildTradeCommitments == chain).
func TestTradeRootsV0MatchPublishedVector(t *testing.T) {
	ordersRoot, err := OrdersRootV0(aliceBobOrders())
	if err != nil {
		t.Fatalf("OrdersRootV0: %v", err)
	}
	if ordersRoot != exampleOrdersRoot {
		t.Fatalf("ordersRoot = %s, want %s (leaf order/padding drift!)", ordersRoot, exampleOrdersRoot)
	}
	tradesRoot := TradesRootV0(aliceBobFills())
	if tradesRoot != exampleTradesRoot {
		t.Fatalf("tradesRoot = %s, want %s", tradesRoot, exampleTradesRoot)
	}
}

// Leaf order is fixed by (Sequence, OrderHash): passing orders reversed yields
// the SAME ordersRoot.
func TestOrdersRootV0LeafOrderDeterministic(t *testing.T) {
	orders := aliceBobOrders()
	reversed := []OrderLeaf{orders[1], orders[0]}
	a, _ := OrdersRootV0(orders)
	b, err := OrdersRootV0(reversed)
	if err != nil {
		t.Fatalf("OrdersRootV0 reversed: %v", err)
	}
	if a != b {
		t.Fatalf("ordersRoot must be independent of input order: %s vs %s", a, b)
	}
}

// Fills are committed in matching order — reordering changes tradesRoot.
func TestTradesRootV0OrderMatters(t *testing.T) {
	f := aliceBobFills()
	second := FillLeaf{
		TradeID: "0xabc", Market: "ATOM/USDC", MakerOrderHash: bobOrderHash, TakerOrderHash: exampleOrderHash,
		Price: "100", Qty: "5", MakerFee: "1", TakerFee: "2", Buyer: "bob", Seller: "alice",
	}
	ab := TradesRootV0([]FillLeaf{f[0], second})
	ba := TradesRootV0([]FillLeaf{second, f[0]})
	if ab == ba {
		t.Fatal("tradesRoot must depend on fill order")
	}
}

func TestEmptyRootsV0AreStable(t *testing.T) {
	if EmptyOrdersRootV0() == "" || EmptyTradesRootV0() == "" {
		t.Fatal("empty sentinels must be non-empty")
	}
	// Empty batch differs from a populated one.
	if o, _ := OrdersRootV0(aliceBobOrders()); o == EmptyOrdersRootV0() {
		t.Fatal("populated ordersRoot must differ from empty sentinel")
	}
}

func TestOrdersRootV0RejectsDuplicateNullifier(t *testing.T) {
	o := aliceBobOrders()[0]
	if _, err := OrdersRootV0([]OrderLeaf{o, o}); err == nil {
		t.Fatal("expected duplicate order nullifier to be rejected")
	}
}

// In-circuit v1 binding: the circuit folds the leaves to the same v1 roots the
// helper computes, and proves.
func TestTradeRootBindingCircuitV1AcceptsBatch(t *testing.T) {
	input, err := BuildTradeRootBindingCircuitV1Input(aliceBobOrders(), aliceBobFills())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	// Circuit-expected roots equal the out-of-circuit v1 helper (agreement).
	_, ordersHex, _ := OrdersRootV1Field(aliceBobOrders())
	_, tradesHex := TradesRootV1Field(aliceBobFills())
	if input.ExpectedOrdersRoot != ordersHex || input.ExpectedTradesRoot != tradesHex {
		t.Fatalf("circuit roots disagree with helper: %s/%s vs %s/%s",
			input.ExpectedOrdersRoot, input.ExpectedTradesRoot, ordersHex, tradesHex)
	}
	proof, err := ProveTradeRootBindingCircuitV1(input)
	if err != nil {
		t.Fatalf("prove batch binding: %v", err)
	}
	if len(proof) <= 2 {
		t.Fatal("expected non-empty proof")
	}
}

// Tamper: change one fill field (price) while keeping the public root -> the
// recomputed tradesRoot no longer matches -> prove fails.
func TestTradeRootBindingCircuitV1RejectsTamper(t *testing.T) {
	input, err := BuildTradeRootBindingCircuitV1Input(aliceBobOrders(), aliceBobFills())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	input.TamperFillPrice("999") // real fill price was 100
	if _, err := ProveTradeRootBindingCircuitV1(input); err == nil {
		t.Fatal("expected tampered fill price to fail root binding")
	}
}

// v1 field-native roots differ from v0 SHA-256 roots (migration gap §10).
func TestTradeRootsV1DifferFromV0(t *testing.T) {
	_, ordersV1, _ := OrdersRootV1Field(aliceBobOrders())
	if ordersV1 == exampleOrdersRoot {
		t.Fatal("v1 ordersRoot must differ from v0")
	}
	_, tradesV1 := TradesRootV1Field(aliceBobFills())
	if tradesV1 == exampleTradesRoot {
		t.Fatal("v1 tradesRoot must differ from v0")
	}
}

func TestBuildTradeRootRejectsWrongArity(t *testing.T) {
	if _, err := BuildTradeRootBindingCircuitV1Input(aliceBobOrders()[:1], aliceBobFills()); err == nil {
		t.Fatal("expected wrong order arity to be rejected")
	}
}
