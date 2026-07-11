package prover

import (
	"errors"
	"strings"
	"testing"

	"github.com/zhenjb/gazk/contract"
)

// eight well-formed public inputs in the locked trade layout (zk_trade_io.md §6).
func validTradePublicInputs() []string {
	return []string{
		"0xdc03bee6", // oldStateRoot
		"0xc79bc87c", // newStateRoot
		"0x01",       // depositsRoot
		"0x02",       // withdrawalsRoot
		"0x03",       // nullifiersRoot
		"0x04",       // withdrawOutputsRoot
		"0xe0485ea2", // tradesRoot
		"0x798b004f", // ordersRoot
	}
}

func validTradeBundle() contract.ProofBundle {
	return contract.ProofBundle{
		Proof:             "0xdeadbeef",
		PublicInputs:      validTradePublicInputs(),
		VerificationKeyID: TradeVerificationKeyID,
	}
}

func validTradeUpdate() contract.SettlementUpdate {
	return contract.SettlementUpdate{
		BatchID:      "batch-trade-1",
		OldStateRoot: "0xdc03bee6",
		NewStateRoot: "0xc79bc87c",
	}
}

func TestVerifyTradeStubAcceptsWellFormedBundle(t *testing.T) {
	s := NewService()
	if err := s.VerifyTrade(validTradeUpdate(), validTradeBundle(), validTradePublicInputs()); err != nil {
		t.Fatalf("stub must accept a well-formed bundle, got: %v", err)
	}
}

func TestVerifyTradeStubRejects(t *testing.T) {
	s := NewService()

	cases := []struct {
		name    string
		mutate  func(*contract.SettlementUpdate, *contract.ProofBundle, *[]string)
		wantSub string
	}{
		{
			name: "empty proof",
			mutate: func(_ *contract.SettlementUpdate, b *contract.ProofBundle, _ *[]string) {
				b.Proof = "   "
			},
			wantSub: "proof is empty",
		},
		{
			name: "caller public inputs not 8",
			mutate: func(_ *contract.SettlementUpdate, _ *contract.ProofBundle, pi *[]string) {
				*pi = (*pi)[:6]
			},
			wantSub: "must contain 8 values",
		},
		{
			name: "proof bundle public inputs not 8",
			mutate: func(_ *contract.SettlementUpdate, b *contract.ProofBundle, _ *[]string) {
				b.PublicInputs = b.PublicInputs[:7]
			},
			wantSub: "must contain 8 values",
		},
		{
			name: "public input empty hex",
			mutate: func(_ *contract.SettlementUpdate, b *contract.ProofBundle, pi *[]string) {
				(*pi)[6] = "0x"
				b.PublicInputs[6] = "0x"
			},
			wantSub: "must not be empty hex",
		},
		{
			name: "public input missing 0x prefix",
			mutate: func(_ *contract.SettlementUpdate, b *contract.ProofBundle, pi *[]string) {
				(*pi)[7] = "798b004f"
				b.PublicInputs[7] = "798b004f"
			},
			wantSub: "must have 0x prefix",
		},
		{
			name: "claimed != expected (layout drift)",
			mutate: func(_ *contract.SettlementUpdate, b *contract.ProofBundle, _ *[]string) {
				b.PublicInputs[6] = "0xffffffff"
			},
			wantSub: "mismatch",
		},
		{
			name: "wrong vkId",
			mutate: func(_ *contract.SettlementUpdate, b *contract.ProofBundle, _ *[]string) {
				b.VerificationKeyID = "gazk-balance-smoke-v1"
			},
			wantSub: "verificationKeyId mismatch",
		},
		{
			name: "missing state roots",
			mutate: func(u *contract.SettlementUpdate, _ *contract.ProofBundle, _ *[]string) {
				u.OldStateRoot = ""
			},
			wantSub: "state roots are required",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			update := validTradeUpdate()
			bundle := validTradeBundle()
			pi := validTradePublicInputs()

			tc.mutate(&update, &bundle, &pi)

			err := s.VerifyTrade(update, bundle, pi)
			if err == nil {
				t.Fatalf("expected rejection for %q, got nil", tc.name)
			}
			if !errors.Is(err, ErrTradeProofRejected) {
				t.Fatalf("expected ErrTradeProofRejected, got: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

func TestTradeVerifierArtifactPublishesVkIdAndLayout(t *testing.T) {
	a := NewService().TradeVerifierArtifact()

	if a.VerificationKeyID != "gazk-trade-v1" {
		t.Fatalf("vkId = %q, want gazk-trade-v1", a.VerificationKeyID)
	}
	if a.PublicInputCount != 8 {
		t.Fatalf("publicInputCount = %d, want 8", a.PublicInputCount)
	}
	if len(a.PublicInputNames) != 8 {
		t.Fatalf("publicInputNames len = %d, want 8", len(a.PublicInputNames))
	}
	if a.PublicInputNames[6] != "batchCommitments.tradesRoot" || a.PublicInputNames[7] != "batchCommitments.ordersRoot" {
		t.Fatalf("appended layout drift: [6]=%q [7]=%q", a.PublicInputNames[6], a.PublicInputNames[7])
	}
	// ZK-T09: keys now exist, so the artifact carries the real verifying key.
	if a.Stub {
		t.Fatal("trade verifier artifact must be real (Stub=false) once ZK-T09 keys exist")
	}
	if a.VerifyingKey == "" {
		t.Fatal("expected a real verifying key hex in the artifact")
	}
}
