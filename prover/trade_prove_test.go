package prover

import (
	"strings"
	"testing"

	"github.com/zhenjb/gazk/contract"
)

func canonicalTradeProveRequest() contract.TradeProveRequest {
	const aliceHash = "0x60ab102de75186520e5bc75fee0b76583567323946d50dddafcd0b55334dbb8a"
	const bobHash = "0xbeeae7ff0bad0b8e19594892537e52e77a17cfd0b6c92ebfe105911c1897749f"
	const tradeID = "0xc0b11f3a4fbf7ca3ba85c2b90a7c4c6337da9001e14dd2b5bf0d149a8c06cd14"
	return contract.TradeProveRequest{
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

// DoD: /prove for a real trade batch returns a proofBundle with 8 public inputs +
// vkId gazk-trade-v1, and the proof verifies (== the on-chain check B runs).
func TestProveRouteReturnsTradeProofBundle(t *testing.T) {
	s := NewService()
	bundle, err := s.Prove(contract.ProveRequest{Trade: ptrTradeReq(canonicalTradeProveRequest())})
	if err != nil {
		t.Fatalf("prove trade: %v", err)
	}
	if bundle.VerificationKeyID != "gazk-trade-v1" {
		t.Fatalf("vkId = %q, want gazk-trade-v1", bundle.VerificationKeyID)
	}
	if len(bundle.PublicInputs) != 8 {
		t.Fatalf("expected 8 public inputs, got %d", len(bundle.PublicInputs))
	}
	if !strings.HasPrefix(bundle.Proof, "0x") || len(bundle.Proof) <= 2 {
		t.Fatalf("expected non-empty proof")
	}

	// The bundle verifies against the same vk (ZK-T10 loop closed).
	if err := s.VerifyTrade(
		contract.SettlementUpdate{BatchID: "b", OldStateRoot: bundle.PublicInputs[0], NewStateRoot: bundle.PublicInputs[1]},
		bundle, bundle.PublicInputs,
	); err != nil {
		t.Fatalf("proved bundle must verify: %v", err)
	}
}

// A witness that violates a trade rule (non-crossing price) fails proving with a
// clear error D can act on.
func TestProveTradeRejectsNonCrossingWitness(t *testing.T) {
	s := NewService()
	req := canonicalTradeProveRequest()
	req.BidPrice = "99" // bid < ask 100 -> non-crossing, circuit unsatisfiable
	req.FillPrice = "99"

	_, err := s.Prove(contract.ProveRequest{Trade: ptrTradeReq(req)})
	if err == nil {
		t.Fatal("expected non-crossing witness to fail proving")
	}
	if !strings.Contains(err.Error(), "does not satisfy") && !strings.Contains(err.Error(), "invalid prove request") {
		t.Fatalf("expected a clear constraint error, got: %v", err)
	}
}

// Missing orders/fills -> clear request error.
func TestProveTradeRejectsEmptyBatch(t *testing.T) {
	s := NewService()
	_, err := s.Prove(contract.ProveRequest{Trade: &contract.TradeProveRequest{}})
	if err == nil {
		t.Fatal("expected empty trade batch to be rejected")
	}
}

func ptrTradeReq(r contract.TradeProveRequest) *contract.TradeProveRequest { return &r }
