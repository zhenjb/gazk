package prover

import (
	"strings"
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

func TestVerifyAcceptsGeneratedProof(t *testing.T) {
	service := NewService()

	proofBundle, err := service.Prove(validAliceProveRequest())
	if err != nil {
		t.Fatalf("prove valid Alice transition: %v", err)
	}

	err = service.Verify(contract.VerifyRequest{
		SettlementUpdate: validAliceProveRequest().SettlementUpdate,
		BatchCommitments: validAliceProveRequest().BatchCommitments,
		ProofBundle:      proofBundle,
	})
	if err != nil {
		t.Fatalf("verify generated proof: %v", err)
	}
}

func TestVerifyRejectsTamperedProofBytes(t *testing.T) {
	service := NewService()

	proofBundle, err := service.Prove(validAliceProveRequest())
	if err != nil {
		t.Fatalf("prove valid Alice transition: %v", err)
	}

	proofBundle.Proof = "0x" + strings.Repeat("00", (len(proofBundle.Proof)-2)/2)

	err = service.Verify(contract.VerifyRequest{
		SettlementUpdate: validAliceProveRequest().SettlementUpdate,
		BatchCommitments: validAliceProveRequest().BatchCommitments,
		ProofBundle:      proofBundle,
	})
	if err == nil {
		t.Fatalf("expected tampered proof to fail")
	}
}

func TestVerifyRejectsPublicInputMismatch(t *testing.T) {
	service := NewService()

	proofBundle, err := service.Prove(validAliceProveRequest())
	if err != nil {
		t.Fatalf("prove valid Alice transition: %v", err)
	}

	proofBundle.PublicInputs[1] = "0xtamperedRoot"

	err = service.Verify(contract.VerifyRequest{
		SettlementUpdate: validAliceProveRequest().SettlementUpdate,
		BatchCommitments: validAliceProveRequest().BatchCommitments,
		ProofBundle:      proofBundle,
	})
	if err == nil {
		t.Fatalf("expected public input mismatch to fail")
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

func TestProveRejectsInvalidNullifier(t *testing.T) {
	service := NewService()

	req := validAliceProveRequest()
	req.SettlementUpdate.Withdrawals[0].Nullifier = "0xbadnullifier"

	_, err := service.Prove(req)
	if err == nil {
		t.Fatalf("expected invalid nullifier to fail")
	}
}

func TestProveRejectsInvalidDestinationHash(t *testing.T) {
	service := NewService()

	req := validAliceProveRequest()
	req.SettlementUpdate.Withdrawals[0].DestinationHash = "0xbaddestinationhash"

	_, err := service.Prove(req)
	if err == nil {
		t.Fatalf("expected invalid destinationHash to fail")
	}
}

func TestNullifierForMatchesCanonicalAliceVector(t *testing.T) {
	got, err := NullifierFor("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive nullifier: %v", err)
	}

	want := "0xac441258225277bef8aa13fc03cf4d9e8f10549fbdca6b860c89dd0c4148ea91"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestDestinationHashForMatchesCanonicalAliceVector(t *testing.T) {
	got, err := DestinationHashFor("cosmos1alice")
	if err != nil {
		t.Fatalf("derive destination hash: %v", err)
	}

	want := "0xa75ac956249df4c45b83281c5af6187c59df9709fd1c25b5e61b12d71a8eb417"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func validAliceProveRequest() contract.ProveRequest {
	nullifier, err := NullifierFor("mock-user-secret", "1")
	if err != nil {
		panic(err)
	}

	destinationHash, err := DestinationHashFor("cosmos1alice")
	if err != nil {
		panic(err)
	}

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
					DestinationHash: destinationHash,
					Nullifier:       nullifier,
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
