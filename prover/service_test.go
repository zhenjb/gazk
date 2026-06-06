package prover

import (
	"testing"

	"github.com/zhenjb/gazk/contract"
)

func TestProveValidAliceBalanceTransition(t *testing.T) {
	service := NewService()

	resp, err := service.Prove(validAliceProveRequest())
	if err != nil {
		t.Fatalf("prove valid Alice transition: %v", err)
	}

	if resp.Proof == "" {
		t.Fatalf("expected proof")
	}

	if resp.VerificationKeyID != VerificationKeyID {
		t.Fatalf("expected verificationKeyId=%q, got %q", VerificationKeyID, resp.VerificationKeyID)
	}

	if len(resp.PublicInputs) != 6 {
		t.Fatalf("expected 6 public inputs, got %d", len(resp.PublicInputs))
	}
}

func TestProveRejectsInvalidBalanceTransition(t *testing.T) {
	service := NewService()

	req := validAliceProveRequest()
	req.Witness.Accounts[0].NewBalance = "70"

	_, err := service.Prove(req)
	if err == nil {
		t.Fatalf("expected invalid balance transition to fail")
	}
}

func validAliceProveRequest() contract.ProveRequest {
	return contract.ProveRequest{
		SettlementUpdate: contract.SettlementUpdate{
			BatchID:      "batch-1",
			OldStateRoot: "0xrootA",
			NewStateRoot: "0xrootB",
			Deposits: []contract.SettlementDeposit{
				{
					DepositID: "dep-1",
					Owner:     "cosmos1alice",
					Denom:     "uusdc",
					Amount:    "100",
				},
			},
			Withdrawals: []contract.SettlementWithdrawal{
				{
					WithdrawID:      "wd-1",
					Owner:           "cosmos1alice",
					Denom:           "uusdc",
					Amount:          "40",
					Destination:     "cosmos1alice",
					DestinationHash: "0xdestination",
					Nullifier:       "0xnullifier",
				},
			},
		},
		BatchCommitments: contract.BatchCommitments{
			DepositsRoot:        "0xdepositsRoot",
			WithdrawalsRoot:     "0xwithdrawalsRoot",
			NullifiersRoot:      "0xnullifiersRoot",
			WithdrawOutputsRoot: "0xwithdrawOutputsRoot",
		},
		Witness: contract.Witness{
			Accounts: []contract.WitnessAccount{
				{
					Owner:      "cosmos1alice",
					UserSecret: "mock-user-secret",
					Nonce:      "1",
					OldBalance: "0",
					NewBalance: "60",
				},
			},
		},
	}
}
