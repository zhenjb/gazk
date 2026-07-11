package prover

import (
	"testing"
)

// STATE-T11 alice-buy/bob-sell cross at price 100. Maker = alice (bid, rested
// first), so fillPrice = bidPrice = 100.
func TestPriceCrossingCircuitV1AcceptsCrossingVector(t *testing.T) {
	input, err := BuildPriceCrossingCircuitV1Input("100", "100", "100", true)
	if err != nil {
		t.Fatalf("build crossing input: %v", err)
	}
	proof, err := ProvePriceCrossingCircuitV1(input)
	if err != nil {
		t.Fatalf("prove crossing vector: %v", err)
	}
	if len(proof) <= 2 {
		t.Fatalf("expected non-empty proof, got %q", proof)
	}
}

// Bid strictly above ask, maker = ask (sell rested first): fill = askPrice.
func TestPriceCrossingCircuitV1AcceptsMakerAsk(t *testing.T) {
	// bid 101 >= ask 100; maker is the ask, fill = 100; 100 in [100,101].
	input, err := BuildPriceCrossingCircuitV1Input("101", "100", "100", false)
	if err != nil {
		t.Fatalf("build maker-ask input: %v", err)
	}
	if _, err := ProvePriceCrossingCircuitV1(input); err != nil {
		t.Fatalf("prove maker-ask crossing: %v", err)
	}
}

func TestPriceCrossingCircuitV1RejectsNonCrossing(t *testing.T) {
	// bid 99 < ask 100 → not crossing. fill set to maker (bid) price 99.
	input, err := BuildPriceCrossingCircuitV1Input("99", "100", "99", true)
	if err != nil {
		t.Fatalf("build non-crossing input: %v", err)
	}
	if _, err := ProvePriceCrossingCircuitV1(input); err == nil {
		t.Fatal("expected non-crossing (ask > bid) to fail proving")
	}
}

func TestPriceCrossingCircuitV1RejectsWrongFillPrice(t *testing.T) {
	// maker is bid (100); fill must be 100 but operator claims 100.5 -> fail.
	input, err := BuildPriceCrossingCircuitV1Input("100", "100", "100.5", true)
	if err != nil {
		t.Fatalf("build wrong-fill input: %v", err)
	}
	if _, err := ProvePriceCrossingCircuitV1(input); err == nil {
		t.Fatal("expected fill != makerPrice to fail proving")
	}
}

func TestPriceCrossingCircuitV1RejectsFillOutsideBand(t *testing.T) {
	// Force fill above bid by lying about makerIsBid: maker=ask(100) but fill=105
	// which is > bid(100). fill != makerPrice AND fill > bid — must fail.
	input, err := BuildPriceCrossingCircuitV1Input("100", "100", "105", false)
	if err != nil {
		t.Fatalf("build out-of-band input: %v", err)
	}
	if _, err := ProvePriceCrossingCircuitV1(input); err == nil {
		t.Fatal("expected fill outside [ask,bid] to fail proving")
	}
}

// Scale alignment must match P3: "100" and "100.00" are economically equal, and
// a fractional-tick market ("100.5" vs "100.25") must map onto a shared scale.
func TestPriceCrossingCircuitV1ScaleAlignment(t *testing.T) {
	// bid 100.50 >= ask 100.25, maker=bid, fill=100.50. Common scale = 2.
	input, err := BuildPriceCrossingCircuitV1Input("100.50", "100.25", "100.5", true)
	if err != nil {
		t.Fatalf("build scaled input: %v", err)
	}
	if input.CommonScale != 2 {
		t.Fatalf("common scale = %d, want 2", input.CommonScale)
	}
	// bid 10050, ask 10025, fill 10050 at scale 2.
	if input.BidPrice.Int64() != 10050 || input.AskPrice.Int64() != 10025 || input.FillPrice.Int64() != 10050 {
		t.Fatalf("scaled ints wrong: bid=%s ask=%s fill=%s", input.BidPrice, input.AskPrice, input.FillPrice)
	}
	if _, err := ProvePriceCrossingCircuitV1(input); err != nil {
		t.Fatalf("prove scaled crossing: %v", err)
	}
}

// "100" and "100.00" scale-align to equal integers (P3 cmpDecimal == 0).
func TestPriceCrossingCircuitV1TrailingZerosEqual(t *testing.T) {
	input, err := BuildPriceCrossingCircuitV1Input("100.00", "100", "100.000", true)
	if err != nil {
		t.Fatalf("build trailing-zeros input: %v", err)
	}
	if input.BidPrice.Cmp(input.AskPrice) != 0 || input.BidPrice.Cmp(input.FillPrice) != 0 {
		t.Fatalf("trailing zeros not equal after align: bid=%s ask=%s fill=%s", input.BidPrice, input.AskPrice, input.FillPrice)
	}
	if _, err := ProvePriceCrossingCircuitV1(input); err != nil {
		t.Fatalf("prove trailing-zeros crossing: %v", err)
	}
}

func TestPriceCrossingCircuitV1RejectsBadDecimals(t *testing.T) {
	bad := [][3]string{
		{"", "100", "100"},
		{"100", "10.0.0", "100"},
		{"-1", "100", "100"},
		{"1e5", "100", "100"},
	}
	for i, c := range bad {
		if _, err := BuildPriceCrossingCircuitV1Input(c[0], c[1], c[2], true); err == nil {
			t.Fatalf("case %d: expected bad decimal to fail input build", i)
		}
	}
}
