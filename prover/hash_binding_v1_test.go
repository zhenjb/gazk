package prover

import (
	"testing"

	"github.com/zhenjb/gazk/contract"
)

func TestProveV1HashModeAcceptsV1AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	_, err := service.Prove(validAliceProveRequestV1())
	if err != nil {
		t.Fatalf("expected v1 hash mode to accept v1 Alice vector: %v", err)
	}
}

func TestProveV1HashModeRejectsV0AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV1MiMC.String())

	_, err := service.Prove(validAliceProveRequest())
	if err == nil {
		t.Fatalf("expected v1 hash mode to reject v0 Alice vector")
	}
}

func TestProveV0HashModeRejectsV1AliceVector(t *testing.T) {
	service := NewServiceWithHashMode(HashModeV0SHA256.String())

	_, err := service.Prove(validAliceProveRequestV1())
	if err == nil {
		t.Fatalf("expected v0 hash mode to reject v1 Alice vector")
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
	nullifier, err := NullifierForV1("mock-user-secret", "1")
	if err != nil {
		panic(err)
	}

	destinationHash, err := DestinationHashForV1("cosmos1alice")
	if err != nil {
		panic(err)
	}

	req := validAliceProveRequest()
	req.SettlementUpdate.Withdrawals[0].Nullifier = nullifier
	req.SettlementUpdate.Withdrawals[0].DestinationHash = destinationHash

	return req
}
