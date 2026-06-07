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

	destinationHash, err := prover.DestinationHashFor("cosmos1alice")
	if err != nil {
		t.Fatalf("derive destination hash: %v", err)
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

func TestHTTPVerifyAcceptsGeneratedProof(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	nullifier, err := prover.NullifierFor("mock-user-secret", "1")
	if err != nil {
		t.Fatalf("derive nullifier: %v", err)
	}

	destinationHash, err := prover.DestinationHashFor("cosmos1alice")
	if err != nil {
		t.Fatalf("derive destination hash: %v", err)
	}

	proveReq := contract.ProveRequest{
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

	rawProve, err := json.Marshal(proveReq)
	if err != nil {
		t.Fatalf("marshal prove request: %v", err)
	}

	proveHTTPReq := httptest.NewRequest(http.MethodPost, "/prove", bytes.NewReader(rawProve))
	proveHTTPReq.Header.Set("Content-Type", "application/json")

	proveRec := httptest.NewRecorder()
	handler.ServeHTTP(proveRec, proveHTTPReq)

	if proveRec.Code != http.StatusOK {
		t.Fatalf("expected prove status 200, got %d body=%s", proveRec.Code, proveRec.Body.String())
	}

	var proveResp contract.ProveResponse
	if err := json.NewDecoder(proveRec.Body).Decode(&proveResp); err != nil {
		t.Fatalf("decode prove response: %v", err)
	}

	verifyReq := contract.VerifyRequest{
		SettlementUpdate: proveReq.SettlementUpdate,
		BatchCommitments: proveReq.BatchCommitments,
		ProofBundle:      proveResp.ProofBundle,
	}

	rawVerify, err := json.Marshal(verifyReq)
	if err != nil {
		t.Fatalf("marshal verify request: %v", err)
	}

	verifyHTTPReq := httptest.NewRequest(http.MethodPost, "/verify", bytes.NewReader(rawVerify))
	verifyHTTPReq.Header.Set("Content-Type", "application/json")

	verifyRec := httptest.NewRecorder()
	handler.ServeHTTP(verifyRec, verifyHTTPReq)

	if verifyRec.Code != http.StatusOK {
		t.Fatalf("expected verify status 200, got %d body=%s", verifyRec.Code, verifyRec.Body.String())
	}

	var verifyResp contract.VerifyResponse
	if err := json.NewDecoder(verifyRec.Body).Decode(&verifyResp); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}

	if !verifyResp.Valid {
		t.Fatalf("expected verify valid=true, got error=%q", verifyResp.Error)
	}
}

func TestHTTPHealthExposesHashMode(t *testing.T) {
	handler := NewHTTPServer(prover.NewServiceWithHashMode("")).Routes()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if resp["hashMode"] != prover.HashModeV0SHA256.String() {
		t.Fatalf("expected hashMode=%q, got %q", prover.HashModeV0SHA256.String(), resp["hashMode"])
	}

	if resp["hashV1Id"] != prover.HashV1ID {
		t.Fatalf("expected hashV1Id=%q, got %q", prover.HashV1ID, resp["hashV1Id"])
	}
}
