package prover

import (
	"strings"
	"testing"
	"time"
)

// ZK-T11 — Negative tests + benchmark.
//
// The circuit is only trustworthy when EVERY attack path is blocked (no
// false-accept) and its cost is measured. This file consolidates the trade
// attack surface against the REAL unified circuit (TradeSettlementCircuitV1) and
// the aggregation circuit (MultiWithdrawalCircuitV1), plus a benchmark of
// prove/verify time and constraint count by op count. Numbers land in
// ZK-T11-negative-tests-benchmark.md.

// tamperTrade applies a mutation to the canonical batch.
type tradeNegative struct {
	name   string
	mutate func(*CanonicalTradeBatch)
	stage  string // "build" | "prove" | "verify"
}

// TestZKT11TradeNegativeVectors asserts every tampered trade vector is REJECTED
// at the expected stage — no false-accept.
func TestZKT11TradeNegativeVectors(t *testing.T) {
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	vectors := []tradeNegative{
		{
			name:  "non-crossing (bid < ask)",
			stage: "prove",
			mutate: func(b *CanonicalTradeBatch) {
				b.BidPrice = "99"
				b.FillPrice = "99"
				b.Orders[0].Price = "99" // alice buy price
			},
		},
		{
			name:  "wrong fill price (fill != maker)",
			stage: "prove",
			mutate: func(b *CanonicalTradeBatch) {
				b.FillPrice = "101" // maker price is 100
			},
		},
		{
			name:  "over-reserve (buyer reserved < spend)",
			stage: "prove",
			mutate: func(b *CanonicalTradeBatch) {
				// Reserved 2000 < buyerQuoteOut 2010 -> T05 reserved check fails
				// in-circuit. Cells stay valid so the failure is at prove, not build.
				b.Conservation.BuyerReservedQuoteBefore = "2000"
			},
		},
		{
			name:  "seller fee exceeds notional",
			stage: "build",
			mutate: func(b *CanonicalTradeBatch) {
				b.Conservation.TakerFee = "999999" // seller (taker) fee > notional 2000
			},
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			batch := DefaultCanonicalTradeBatch()
			v.mutate(&batch)

			input, err := BuildTradeSettlementCircuitV1Input(batch)
			if v.stage == "build" {
				if err == nil {
					t.Fatalf("FALSE-ACCEPT: %q should fail at build", v.name)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected build error for %q: %v", v.name, err)
			}

			_, err = engine.Prove(input)
			if v.stage == "prove" {
				if err == nil {
					t.Fatalf("FALSE-ACCEPT: %q produced a proof (must fail proving)", v.name)
				}
				return
			}
			t.Fatalf("vector %q reached unexpected stage", v.name)
		})
	}
}

// TestZKT11VerifyNegativeVectors asserts verify-stage attacks (valid-looking
// proof, tampered public inputs / fake proof) are rejected.
func TestZKT11VerifyNegativeVectors(t *testing.T) {
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

	// sanity: honest proof verifies.
	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("honest proof must verify: %v", err)
	}

	// Each tampered public input must fail verification.
	for i := range input.PublicInputs {
		tampered := append([]string(nil), input.PublicInputs...)
		tampered[i] = "0x" + strings.Repeat("ab", 16)
		if err := engine.VerifyPublicInputs(proof, tampered); err == nil {
			t.Fatalf("FALSE-ACCEPT: tampered public input [%d] verified", i)
		}
	}

	// A fake proof of the right length must fail.
	fake := "0x" + strings.Repeat("00", (len(proof)-2)/2)
	if err := engine.VerifyPublicInputs(fake, input.PublicInputs); err == nil {
		t.Fatal("FALSE-ACCEPT: fake proof verified")
	}
}

// TestZKT11AggregationNegativeVectors covers the ZK-T08a attack surface.
func TestZKT11AggregationNegativeVectors(t *testing.T) {
	// out-of-order nonce -> build guard.
	if _, err := BuildMultiWithdrawalCircuitV1Input("alice", "s", "1000", []WithdrawalOp{
		{Nonce: "3", Amount: "10"}, {Nonce: "2", Amount: "10"},
	}); err == nil {
		t.Fatal("FALSE-ACCEPT: out-of-order nonce accepted")
	}
	// over-withdraw -> build guard.
	if _, err := BuildMultiWithdrawalCircuitV1Input("alice", "s", "10", []WithdrawalOp{
		{Nonce: "1", Amount: "20"},
	}); err == nil {
		t.Fatal("FALSE-ACCEPT: over-withdraw accepted")
	}
	// tampered nullifier -> prove fail.
	in, err := BuildMultiWithdrawalCircuitV1Input("alice", "s", "1000", []WithdrawalOp{{Nonce: "1", Amount: "10"}})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	in.TamperWithdrawalNullifier(0)
	if _, err := ProveMultiWithdrawalCircuitV1(in); err == nil {
		t.Fatal("FALSE-ACCEPT: tampered nullifier proved")
	}
}

// TestZKT11OrderBindingNegativeVectors covers ZK-T03/T06 (forged owner / replay).
func TestZKT11OrderBindingNegativeVectors(t *testing.T) {
	// forged owner: bob reuses alice's order commitment.
	alice, err := BuildOrderHashBindingCircuitV1Input(aliceBuyOrder())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	bobField, _ := OrderOwnerFieldForV1("bob")
	forged := alice
	forged.OwnerField = bobField
	if _, err := ProveOrderHashBindingCircuitV1(forged); err == nil {
		t.Fatal("FALSE-ACCEPT: forged owner proved")
	}

	// replayed order nullifier: wrong owner against alice's nullifier.
	an, err := BuildOrderNullifierCircuitV1Input("alice", exampleOrderHash)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	an.OwnerField = bobField
	if _, err := ProveOrderNullifierCircuitV1(an); err == nil {
		t.Fatal("FALSE-ACCEPT: replayed/forged nullifier proved")
	}
}

// TestZKT11Benchmark measures constraint count + prove/verify time for the trade
// circuit and per-op cost for the aggregation circuit. Logs go to the Report.
func TestZKT11Benchmark(t *testing.T) {
	if testing.Short() {
		t.Skip("benchmark skipped in -short")
	}

	// Trade circuit.
	tStart := time.Now()
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	setup := time.Since(tStart)
	input, err := BuildTradeSettlementCircuitV1Input(DefaultCanonicalTradeBatch())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	pStart := time.Now()
	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}
	proveT := time.Since(pStart)
	vStart := time.Now()
	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("verify: %v", err)
	}
	verifyT := time.Since(vStart)
	t.Logf("[BENCH] TradeSettlementCircuitV1: constraints=%d setup=%v prove=%v verify=%v proof.bytes=%d",
		engine.ccs.GetNbConstraints(), setup.Round(time.Millisecond), proveT.Round(time.Millisecond), verifyT.Round(time.Millisecond), (len(proof)-2)/2)

	// Aggregation circuit: prove time for 1, N/2, N withdrawals.
	ccs, pk, _, err := compileAndSetupMultiWithdrawalCircuit()
	if err != nil {
		t.Fatalf("agg setup: %v", err)
	}
	t.Logf("[BENCH] MultiWithdrawalCircuitV1: constraints=%d maxOps=%d", ccs.GetNbConstraints(), maxWithdrawalsPerProof)
	for _, n := range []int{1, maxWithdrawalsPerProof / 2, maxWithdrawalsPerProof} {
		if n < 1 {
			n = 1
		}
		ops := make([]WithdrawalOp, n)
		for i := range ops {
			ops[i] = WithdrawalOp{Nonce: itoa(i + 1), Amount: "10"}
		}
		in, berr := BuildMultiWithdrawalCircuitV1Input("alice", "s", "100000", ops)
		if berr != nil {
			t.Fatalf("build n=%d: %v", n, berr)
		}
		start := time.Now()
		if _, perr := proveMultiWithdrawalWithKeys(ccs, pk, in); perr != nil {
			t.Fatalf("prove n=%d: %v", n, perr)
		}
		el := time.Since(start)
		t.Logf("[BENCH] aggregate n=%d ops: prove=%v per-op=%v", n, el.Round(time.Millisecond), (el / time.Duration(n)).Round(time.Millisecond))
	}
}
