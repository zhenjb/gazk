package prover

import (
	"testing"

	"github.com/zhenjb/gazk/contract"
)

func TestProveV1HashModeAcceptsCircuitV1AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	proofBundle, err := service.Prove(validAliceProveRequestV1())
	if err != nil {
		t.Fatalf("expected v1 hash mode to accept circuit v1 Alice vector: %v", err)
	}

	if proofBundle.VerificationKeyID != VerificationKeyIDV1 {
		t.Fatalf("expected v1 verification key id %q, got %q", VerificationKeyIDV1, proofBundle.VerificationKeyID)
	}
}

func TestVerifyV1HashModeAcceptsGeneratedProof(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()
	proofBundle, err := service.Prove(req)
	if err != nil {
		t.Fatalf("prove v1 Alice vector: %v", err)
	}

	err = service.Verify(contract.VerifyRequest{
		SettlementUpdate: req.SettlementUpdate,
		BatchCommitments: req.BatchCommitments,
		ProofBundle:      proofBundle,
	})
	if err != nil {
		t.Fatalf("verify v1 generated proof: %v", err)
	}
}

func TestVerifyV1HashModeRejectsTamperedSettlementNullifier(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()
	proofBundle, err := service.Prove(req)
	if err != nil {
		t.Fatalf("prove v1 Alice vector: %v", err)
	}

	verifyUpdate := req.SettlementUpdate
	verifyUpdate.Withdrawals = append([]contract.SettlementWithdrawal(nil), req.SettlementUpdate.Withdrawals...)
	verifyUpdate.Withdrawals[0].Nullifier = "0x1234"

	err = service.Verify(contract.VerifyRequest{
		SettlementUpdate: verifyUpdate,
		BatchCommitments: req.BatchCommitments,
		ProofBundle:      proofBundle,
	})
	if err == nil {
		t.Fatalf("expected v1 verify to reject tampered settlement nullifier")
	}
}

func TestVerifyV1HashModeRejectsTamperedSettlementDestinationHash(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()
	proofBundle, err := service.Prove(req)
	if err != nil {
		t.Fatalf("prove v1 Alice vector: %v", err)
	}

	verifyUpdate := req.SettlementUpdate
	verifyUpdate.Withdrawals = append([]contract.SettlementWithdrawal(nil), req.SettlementUpdate.Withdrawals...)
	verifyUpdate.Withdrawals[0].DestinationHash = "0x1234"

	err = service.Verify(contract.VerifyRequest{
		SettlementUpdate: verifyUpdate,
		BatchCommitments: req.BatchCommitments,
		ProofBundle:      proofBundle,
	})
	if err == nil {
		t.Fatalf("expected v1 verify to reject tampered settlement destinationHash")
	}
}

func TestProveV1HashModeRejectsTransitionalServiceLevelV1AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()

	transitionalNullifier, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive transitional v1 nullifier: %v", err)
	}
	transitionalDestinationHash, err := DestinationHashForV1("cosmos1alice")
	if err != nil {
		t.Fatalf("derive transitional v1 destination hash: %v", err)
	}

	req.SettlementUpdate.Withdrawals[0].Nullifier = transitionalNullifier
	req.SettlementUpdate.Withdrawals[0].DestinationHash = transitionalDestinationHash

	_, err = service.Prove(req)
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject transitional service-level v1 values")
	}
}

func TestProveV1HashModeRejectsV0AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	_, err := service.Prove(validAliceProveRequest())
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject v0 Alice vector")
	}
}

func TestProveV0HashModeRejectsCircuitV1AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV0SHA256.String())

	_, err := service.Prove(validAliceProveRequestV1())
	if err == nil {
		t.Fatalf("expected v0 hash mode to reject circuit v1 Alice vector")
	}
}

func TestProveV1HashModeRejectsTamperedNullifier(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()
	req.SettlementUpdate.Withdrawals[0].Nullifier = "0xbadnullifier"

	_, err := service.Prove(req)
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject tampered nullifier")
	}
}

func TestProveV1HashModeRejectsTamperedDestinationHash(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()
	req.SettlementUpdate.Withdrawals[0].DestinationHash = "0xbaddestinationhash"

	_, err := service.Prove(req)
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject tampered destinationHash")
	}
}

func TestProveV1HashModeStillRejectsInvalidBalanceTransition(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	req := validAliceProveRequestV1()
	req.Witness.Accounts[0].NewBalance = "70"

	_, err := service.Prove(req)
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject invalid balance transition")
	}
}

func validAliceProveRequestV1() contract.ProveRequest {
	nullifier, err := NullifierCircuitV1Hex("mock-user-secret", "1")
	if err != nil {
		panic(err)
	}

	destinationHash, err := DestinationHashCircuitV1Hex("cosmos1alice")
	if err != nil {
		panic(err)
	}

	req := validAliceProveRequest()
	req.SettlementUpdate.Withdrawals[0].Nullifier = nullifier
	req.SettlementUpdate.Withdrawals[0].DestinationHash = destinationHash

	return req
}
