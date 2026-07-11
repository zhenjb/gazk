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

func tradeVerifyRequest() contract.TradeVerifyRequest {
	inputs := []string{
		"0xdc03bee6", "0xc79bc87c", "0x01", "0x02",
		"0x03", "0x04", "0xe0485ea2", "0x798b004f",
	}
	return contract.TradeVerifyRequest{
		SettlementUpdate: contract.SettlementUpdate{
			BatchID:      "batch-trade-1",
			OldStateRoot: "0xdc03bee6",
			NewStateRoot: "0xc79bc87c",
		},
		ProofBundle: contract.ProofBundle{
			Proof:             "0xdeadbeef",
			PublicInputs:      inputs,
			VerificationKeyID: prover.TradeVerificationKeyID,
		},
		PublicInputs: inputs,
	}
}

// canonicalTradeProveRequest mirrors prover.DefaultCanonicalTradeBatch (alice/bob
// single fill) as an HTTP trade prove request.
func canonicalTradeProveRequest() *contract.TradeProveRequest {
	const aliceHash = "0x60ab102de75186520e5bc75fee0b76583567323946d50dddafcd0b55334dbb8a"
	const bobHash = "0xbeeae7ff0bad0b8e19594892537e52e77a17cfd0b6c92ebfe105911c1897749f"
	const tradeID = "0xc0b11f3a4fbf7ca3ba85c2b90a7c4c6337da9001e14dd2b5bf0d149a8c06cd14"
	return &contract.TradeProveRequest{
		Orders: []contract.TradeOrder{
			{OrderHash: aliceHash, Owner: "alice", Side: "buy", Price: "100", Qty: "20", Remaining: "0", Filled: true, Sequence: 1},
			{OrderHash: bobHash, Owner: "bob", Side: "sell", Price: "100", Qty: "20", Remaining: "0", Filled: true, Sequence: 2},
		},
		Fills: []contract.TradeFill{{
			TradeID: tradeID, Market: "ATOM/USDC", MakerOrderHash: aliceHash, TakerOrderHash: bobHash,
			Price: "100", Qty: "20", MakerFee: "10", TakerFee: "20", Buyer: "alice", Seller: "bob",
		}},
		BidPrice: "100", AskPrice: "100", FillPrice: "100", MakerIsBid: true,
		Conservation: contract.TradeConservation{
			Price: "100", Qty: "20", MakerFee: "10", TakerFee: "20",
			BuyerIsMaker: true, BuyerReservedQuoteBefore: "2010", SellerReservedBaseBefore: "20",
		},
		Cells: []contract.TradeCell{
			{Owner: "alice", Denom: "uusdc", OldBalance: "2010", DeltaIn: "0", DeltaOut: "2010"},
			{Owner: "bob", Denom: "uusdc", OldBalance: "0", DeltaIn: "1980", DeltaOut: "0"},
			{Owner: "zkdex/fee-account", Denom: "uusdc", OldBalance: "0", DeltaIn: "30", DeltaOut: "0"},
		},
	}
}

func postJSON(t *testing.T, handler http.Handler, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(raw))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// ZK-T10: /verify-trade now verifies a REAL proof. Build one via /prove for the
// canonical batch, then verify it round-trips over HTTP.
func TestHTTPVerifyTradeAcceptsRealProof(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	// 1. Prove the canonical trade batch.
	proveReq := contract.ProveRequest{Trade: canonicalTradeProveRequest()}
	proveRec := postJSON(t, handler, "/prove", proveReq)
	if proveRec.Code != http.StatusOK {
		t.Fatalf("prove expected 200, got %d body=%s", proveRec.Code, proveRec.Body.String())
	}
	var proveResp contract.ProveResponse
	if err := json.NewDecoder(proveRec.Body).Decode(&proveResp); err != nil {
		t.Fatalf("decode prove: %v", err)
	}
	if len(proveResp.ProofBundle.PublicInputs) != 8 {
		t.Fatalf("expected 8 public inputs, got %d", len(proveResp.ProofBundle.PublicInputs))
	}

	// 2. Verify it.
	verifyReq := contract.TradeVerifyRequest{
		SettlementUpdate: contract.SettlementUpdate{
			BatchID:      "trade-batch-1",
			OldStateRoot: proveResp.ProofBundle.PublicInputs[0],
			NewStateRoot: proveResp.ProofBundle.PublicInputs[1],
		},
		ProofBundle:  proveResp.ProofBundle,
		PublicInputs: proveResp.ProofBundle.PublicInputs,
	}
	rec := postJSON(t, handler, "/verify-trade", verifyReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp contract.VerifyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("real proof must verify, error=%q", resp.Error)
	}
}

func TestHTTPVerifyTradeStubRejectsEmptyProof(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	req := tradeVerifyRequest()
	req.ProofBundle.Proof = ""

	rec := postJSON(t, handler, "/verify-trade", req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp contract.VerifyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Valid {
		t.Fatal("stub must reject an empty proof")
	}
}

func TestHTTPTradeVerifierArtifactPublishesVkId(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	req := httptest.NewRequest(http.MethodGet, "/trade-verifier-artifact", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var artifact contract.TradeVerifierArtifact
	if err := json.NewDecoder(rec.Body).Decode(&artifact); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if artifact.VerificationKeyID != "gazk-trade-v1" {
		t.Fatalf("vkId = %q, want gazk-trade-v1", artifact.VerificationKeyID)
	}
	// ZK-T09: real keys → Stub=false + non-empty verifying key.
	if artifact.PublicInputCount != 8 || artifact.Stub {
		t.Fatalf("unexpected artifact: count=%d stub=%v", artifact.PublicInputCount, artifact.Stub)
	}
	if artifact.VerifyingKey == "" {
		t.Fatal("expected a real verifying key in the artifact")
	}
}

func TestHTTPHealthExposesTradeVkId(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["tradeVerificationKeyId"] != "gazk-trade-v1" {
		t.Fatalf("expected tradeVerificationKeyId=gazk-trade-v1, got %v", resp["tradeVerificationKeyId"])
	}
	// ZK-T10: the trade verifier is now real, and trade proving is available.
	if resp["tradeVerifierStub"] != false {
		t.Fatalf("expected tradeVerifierStub=false, got %v", resp["tradeVerifierStub"])
	}
	if resp["tradeProve"] != true {
		t.Fatalf("expected tradeProve=true, got %v", resp["tradeProve"])
	}
}
