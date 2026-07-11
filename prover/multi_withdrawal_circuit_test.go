package prover

import (
	"testing"
)

// DoD: one proof settles 3 withdrawals of one account (Alice), each with its own
// nonce — the case that used to fail as "nullifier mismatch".
func TestMultiWithdrawalAcceptsThreeWithdrawals(t *testing.T) {
	input, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "1000", []WithdrawalOp{
		{Nonce: "1", Amount: "100"},
		{Nonce: "2", Amount: "200"},
		{Nonce: "3", Amount: "300"},
	})
	if err != nil {
		t.Fatalf("build 3-withdrawal input: %v", err)
	}
	proof, err := ProveMultiWithdrawalCircuitV1(input)
	if err != nil {
		t.Fatalf("prove 3 withdrawals in one proof: %v", err)
	}
	if len(proof) <= 2 {
		t.Fatal("expected non-empty proof")
	}
}

// Scale to the full N ops/proof.
func TestMultiWithdrawalAcceptsMaxWithdrawals(t *testing.T) {
	ops := make([]WithdrawalOp, maxWithdrawalsPerProof)
	for i := range ops {
		ops[i] = WithdrawalOp{Nonce: itoa(i + 1), Amount: "10"}
	}
	input, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "1000", ops)
	if err != nil {
		t.Fatalf("build max input: %v", err)
	}
	if _, err := ProveMultiWithdrawalCircuitV1(input); err != nil {
		t.Fatalf("prove %d withdrawals: %v", maxWithdrawalsPerProof, err)
	}
}

// Backward compatibility: a single withdrawal still proves (no len==1 restriction
// anymore, but 1 must still work).
func TestMultiWithdrawalAcceptsSingleWithdrawal(t *testing.T) {
	input, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "1000", []WithdrawalOp{
		{Nonce: "1", Amount: "40"},
	})
	if err != nil {
		t.Fatalf("build single input: %v", err)
	}
	if _, err := ProveMultiWithdrawalCircuitV1(input); err != nil {
		t.Fatalf("prove single withdrawal: %v", err)
	}
}

// Nonce order guard (build-level): withdrawals must be strictly increasing.
func TestMultiWithdrawalRejectsOutOfOrderNonce(t *testing.T) {
	_, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "1000", []WithdrawalOp{
		{Nonce: "3", Amount: "100"},
		{Nonce: "2", Amount: "200"}, // out of order
	})
	if err == nil {
		t.Fatal("expected out-of-order nonce to be rejected")
	}
}

// Duplicate nonce (not strictly increasing) rejected.
func TestMultiWithdrawalRejectsDuplicateNonce(t *testing.T) {
	_, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "1000", []WithdrawalOp{
		{Nonce: "1", Amount: "100"},
		{Nonce: "1", Amount: "200"},
	})
	if err == nil {
		t.Fatal("expected duplicate nonce to be rejected")
	}
}

// Over-withdraw (sum exceeds balance) rejected.
func TestMultiWithdrawalRejectsOverWithdraw(t *testing.T) {
	_, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "100", []WithdrawalOp{
		{Nonce: "1", Amount: "60"},
		{Nonce: "2", Amount: "60"}, // 120 > 100
	})
	if err == nil {
		t.Fatal("expected over-withdraw to be rejected")
	}
}

// Circuit-level: a tampered per-withdrawal nullifier must fail proving.
func TestMultiWithdrawalRejectsTamperedNullifier(t *testing.T) {
	input, err := BuildMultiWithdrawalCircuitV1Input("alice", "alice-secret", "1000", []WithdrawalOp{
		{Nonce: "1", Amount: "100"},
		{Nonce: "2", Amount: "200"},
	})
	if err != nil {
		t.Fatalf("build input: %v", err)
	}
	input.TamperWithdrawalNullifier(0)
	if _, err := ProveMultiWithdrawalCircuitV1(input); err == nil {
		t.Fatal("expected tampered nullifier to fail proving")
	}
}

// Bug-fix demonstration: the nonce-vector gives each withdrawal a DISTINCT v0
// nullifier (core NullifierFor), so merging multiple withdrawals no longer
// collides on a single nonce ("nullifier mismatch" no longer reproduces).
func TestMultiWithdrawalNonceVectorDistinctV0Nullifiers(t *testing.T) {
	n1, err := NullifierFor("alice-secret", "1")
	if err != nil {
		t.Fatalf("nullifier 1: %v", err)
	}
	n2, _ := NullifierFor("alice-secret", "2")
	n3, _ := NullifierFor("alice-secret", "3")
	if n1 == n2 || n2 == n3 || n1 == n3 {
		t.Fatal("each withdrawal nonce must yield a distinct nullifier (the fix)")
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
