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

func TestHTTPVerifyTradeStubAccepts(t *testing.T) {
	handler := NewHTTPServer(prover.NewService()).Routes()

	rec := postJSON(t, handler, "/verify-trade", tradeVerifyRequest())
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var resp contract.VerifyResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.Valid {
		t.Fatalf("stub must accept well-formed trade bundle, error=%q", resp.Error)
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
	if resp["tradeVerifierStub"] != true {
		t.Fatalf("expected tradeVerifierStub=true, got %v", resp["tradeVerifierStub"])
	}
}
