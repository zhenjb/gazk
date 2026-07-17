package prover

import "testing"

// INT-2SEQ multi-denom — verification #1 (isolated circuit).
//
// A multi-denom batch relies on the unified trade circuit proving state cells
// that span DIFFERENT denoms. gazk's builder maps each cell's denom independently
// (no "batch denom" anywhere — trade_settlement_builder.go), so this SHOULD hold;
// this test turns "correct on paper" into empirical evidence before any BE work.
func TestTradeCircuitProvesMultiDenomCells(t *testing.T) {
	engine, err := NewTradeCircuitEngine()
	if err != nil {
		t.Fatalf("engine: %v", err)
	}

	batch := DefaultCanonicalTradeBatch()
	// Replace the single-denom (uusdc) cells with THREE different denoms. Roots stay
	// the canonical (single-denom) ones on purpose: the circuit binds the 8 roots
	// OPAQUELY and does NOT re-derive them from cells, so a prove+verify PASS here is
	// ALSO a live demonstration of the "cells not bound to root" MVP limitation
	// (Loại 2) — the roots need not match the cells.
	batch.Cells = []StateCell{
		{Owner: "alice", Denom: "uusdc", OldBalance: "500000", DeltaIn: "0", DeltaOut: "2000"},
		{Owner: "bob", Denom: "uatom", OldBalance: "5000", DeltaIn: "0", DeltaOut: "20"},
		{Owner: "carol", Denom: "uosmo", OldBalance: "0", DeltaIn: "100", DeltaOut: "0"},
	}

	input, err := BuildTradeSettlementCircuitV1Input(batch)
	if err != nil {
		t.Fatalf("build multi-denom input: %v", err)
	}
	proof, err := engine.Prove(input)
	if err != nil {
		t.Fatalf("PROVE multi-denom cells FAILED: %v", err)
	}
	if err := engine.VerifyPublicInputs(proof, input.PublicInputs); err != nil {
		t.Fatalf("VERIFY multi-denom cells FAILED: %v", err)
	}
	t.Logf("multi-denom cells (uusdc / uatom / uosmo) prove+verify OK — circuit carries no single-denom assumption")
}

// The per-cell balance transition still binds under multi-denom: a cell driven
// negative (deltaOut > oldBalance + deltaIn) must be rejected.
func TestTradeCircuitRejectsNegativeMultiDenomCell(t *testing.T) {
	batch := DefaultCanonicalTradeBatch()
	batch.Cells = []StateCell{
		{Owner: "alice", Denom: "uusdc", OldBalance: "500000", DeltaIn: "0", DeltaOut: "2000"},
		{Owner: "bob", Denom: "uatom", OldBalance: "5000", DeltaIn: "0", DeltaOut: "999999"}, // over-debit
	}
	if _, err := BuildTradeSettlementCircuitV1Input(batch); err == nil {
		t.Fatalf("expected rejection: bob/uatom deltaOut exceeds oldBalance (negative newBalance)")
	}
}
