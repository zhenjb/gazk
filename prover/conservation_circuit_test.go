package prover

import (
	"math/big"
	"testing"
)

// STATE-T11 alice/bob: price 100, qty 20 -> notional 2000. Fees maker=10,
// taker=20 (zk_trade_io.md §8). Buyer alice is the maker -> buyerFee=10,
// sellerFee=20. buyerQuoteOut=2010, sellerQuoteIn=1980, fee=30.
func aliceBobConservationFill() ConservationFill {
	return ConservationFill{
		Price:                    "100",
		Qty:                      "20",
		MakerFee:                 "10",
		TakerFee:                 "20",
		BuyerIsMaker:             true,
		BuyerReservedQuoteBefore: "2010",
		SellerReservedBaseBefore: "20",
	}
}

func TestConservationCircuitV1AcceptsValidFill(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(aliceBobConservationFill())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	// Sanity on the derived honest witness.
	if in.QuoteNotional.Int64() != 2000 || in.BuyerQuoteOut.Int64() != 2010 ||
		in.SellerQuoteIn.Int64() != 1980 || in.FeeCredited.Int64() != 30 {
		t.Fatalf("unexpected derived deltas: notional=%s out=%s in=%s fee=%s",
			in.QuoteNotional, in.BuyerQuoteOut, in.SellerQuoteIn, in.FeeCredited)
	}
	proof, err := ProveConservationCircuitV1(in)
	if err != nil {
		t.Fatalf("prove valid fill: %v", err)
	}
	if len(proof) <= 2 {
		t.Fatalf("expected non-empty proof")
	}
}

// Fractional price exercises ScaleFactor != 1: price 0.5 * qty 20 = notional 10.
func TestConservationCircuitV1AcceptsFractionalPrice(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(ConservationFill{
		Price: "0.5", Qty: "20", MakerFee: "0", TakerFee: "0",
		BuyerIsMaker: true, BuyerReservedQuoteBefore: "10", SellerReservedBaseBefore: "20",
	})
	if err != nil {
		t.Fatalf("build fractional input: %v", err)
	}
	if in.ScaleFactor.Int64() != 10 || in.QuoteNotional.Int64() != 10 {
		t.Fatalf("fractional notional wrong: scale=%s notional=%s", in.ScaleFactor, in.QuoteNotional)
	}
	if _, err := ProveConservationCircuitV1(in); err != nil {
		t.Fatalf("prove fractional fill: %v", err)
	}
}

func TestConservationCircuitV1RejectsNonConserving(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(aliceBobConservationFill())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	// Seller receives 10 extra quote out of thin air (in != out + fee).
	in.SellerQuoteIn = big.NewInt(1990)
	if _, err := ProveConservationCircuitV1(in); err == nil {
		t.Fatal("expected non-conserving delta to fail proving")
	}
}

func TestConservationCircuitV1RejectsOverReserve(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(aliceBobConservationFill())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	// Buyer only reserved 2000 but must spend 2010 -> reserved insufficient.
	in.BuyerReservedQuoteBefore = big.NewInt(2000)
	if _, err := ProveConservationCircuitV1(in); err == nil {
		t.Fatal("expected over-reserve (reserved < spend) to fail proving")
	}
}

func TestConservationCircuitV1RejectsSellerOverReserveBase(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(aliceBobConservationFill())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	in.SellerReservedBaseBefore = big.NewInt(19) // needs 20
	if _, err := ProveConservationCircuitV1(in); err == nil {
		t.Fatal("expected seller base over-reserve to fail proving")
	}
}

func TestConservationCircuitV1RejectsBadFee(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(aliceBobConservationFill())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	// Buyer secretly pays no fee (BuyerQuoteOut = notional) while buyerFee=10.
	in.BuyerQuoteOut = big.NewInt(2000)
	if _, err := ProveConservationCircuitV1(in); err == nil {
		t.Fatal("expected bad fee delta to fail proving")
	}
}

func TestConservationCircuitV1RejectsInflatedFeeCredit(t *testing.T) {
	in, err := BuildConservationCircuitV1Input(aliceBobConservationFill())
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	in.FeeCredited = big.NewInt(40) // real fee is 30
	if _, err := ProveConservationCircuitV1(in); err == nil {
		t.Fatal("expected inflated fee credit to fail proving")
	}
}

func TestConservationCircuitV1RejectsNonWholeInputs(t *testing.T) {
	// Notional must be whole: price 100.3 * qty 1 = 100.3 -> not whole units.
	if _, err := BuildConservationCircuitV1Input(ConservationFill{
		Price: "100.3", Qty: "1", MakerFee: "0", TakerFee: "0",
		BuyerIsMaker: true, BuyerReservedQuoteBefore: "101", SellerReservedBaseBefore: "1",
	}); err == nil {
		t.Fatal("expected non-whole notional to fail input build")
	}
	// Seller fee exceeding notional is rejected at build.
	if _, err := BuildConservationCircuitV1Input(ConservationFill{
		Price: "10", Qty: "1", MakerFee: "0", TakerFee: "999",
		BuyerIsMaker: true, BuyerReservedQuoteBefore: "10", SellerReservedBaseBefore: "1",
	}); err == nil {
		t.Fatal("expected seller fee > notional to fail input build")
	}
}
