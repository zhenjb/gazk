package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zhenjb/gazk/contract"
	"github.com/zhenjb/gazk/prover"
)

func TestHTTPProveReturnsProofBundleWithSixPublicInputs(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	nullifier, err := prover.NullifierFor("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive nullifier: %v", err)
	}

	reqBody := contract.ProveRequest{
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

	raw, err := json.Marshal(reqBody)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp contract.ProveResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp.ProofBundle.Proof == "" {
		t.Fatalf("expected proof")
	}

	if resp.ProofBundle.VerificationKeyID != prover.VerificationKeyID {
		t.Fatalf("expected verificationKeyId=%q, got %q", prover.VerificationKeyID, resp.ProofBundle.VerificationKeyID)
	}

	if len(resp.ProofBundle.PublicInputs) != 6 {
		t.Fatalf("expected 6 public inputs, got %d", len(resp.ProofBundle.PublicInputs))
	}

	expected := []string{
		"0xrootA",
		"0xrootB",
		"0xdepositsRoot",
		"0xwithdrawalsRoot",
		"0xnullifiersRoot",
		"0xwithdrawOutputsRoot",
	}

	for i := range expected {
		if resp.ProofBundle.PublicInputs[i] != expected[i] {
			t.Fatalf("publicInputs[%d]: expected %q, got %q", i, expected[i], resp.ProofBundle.PublicInputs[i])
		}
	}
}
