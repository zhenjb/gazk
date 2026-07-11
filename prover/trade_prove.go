package prover

import (
	"fmt"

	"github.com/zhenjb/gazk/contract"
)

// ZK-T10 — trade prove path.
//
// When a /prove request carries a Trade block, the service routes here: it maps
// the HTTP trade batch to the unified circuit's canonical batch, builds the
// witness, runs groth16.Prove against the ZK-T09 keys, and returns a proofBundle
// with the 8 public inputs and vkId gazk-trade-v1. Core deposit/withdraw batches
// (Trade == nil) never reach this path, so their HTTP contract is unchanged.

// ProveTrade produces a real trade proofBundle from a trade batch. Errors are
// wrapped with ErrInvalidProveRequest / the constraint failure so D can debug
// (mirrors the core "nullifier mismatch" style).
func (s *Service) ProveTrade(req contract.TradeProveRequest) (contract.ProofBundle, error) {
	engine, err := s.tradeEngine()
	if err != nil {
		return contract.ProofBundle{}, fmt.Errorf("%w: trade circuit engine: %v", ErrInvalidProveRequest, err)
	}

	batch, err := mapTradeProveRequest(req)
	if err != nil {
		return contract.ProofBundle{}, fmt.Errorf("%w: %v", ErrInvalidProveRequest, err)
	}

	input, err := BuildTradeSettlementCircuitV1Input(batch)
	if err != nil {
		return contract.ProofBundle{}, fmt.Errorf("%w: build trade witness: %v", ErrInvalidProveRequest, err)
	}

	proof, err := engine.Prove(input)
	if err != nil {
		// A constraint violation surfaces here — the witness does not satisfy the
		// trade rules (price/conservation/root/transition).
		return contract.ProofBundle{}, fmt.Errorf("%w: trade witness does not satisfy circuit: %v", ErrInvalidProveRequest, err)
	}

	return contract.ProofBundle{
		Proof:             proof,
		PublicInputs:      input.PublicInputs,
		VerificationKeyID: TradeVerificationKeyID,
	}, nil
}

// mapTradeProveRequest converts the HTTP trade batch into the circuit's canonical
// batch (with sensible defaults for the empty core-root sentinels).
func mapTradeProveRequest(req contract.TradeProveRequest) (CanonicalTradeBatch, error) {
	if len(req.Orders) == 0 || len(req.Fills) == 0 {
		return CanonicalTradeBatch{}, fmt.Errorf("trade batch requires orders and fills")
	}

	orders := make([]OrderLeaf, len(req.Orders))
	for i, o := range req.Orders {
		orders[i] = OrderLeaf{
			OrderHash: o.OrderHash, Owner: o.Owner, Side: o.Side, Price: o.Price,
			Qty: o.Qty, Remaining: o.Remaining, Filled: o.Filled, Sequence: o.Sequence,
		}
	}
	fills := make([]FillLeaf, len(req.Fills))
	for i, f := range req.Fills {
		fills[i] = FillLeaf{
			TradeID: f.TradeID, Market: f.Market, MakerOrderHash: f.MakerOrderHash,
			TakerOrderHash: f.TakerOrderHash, Price: f.Price, Qty: f.Qty,
			MakerFee: f.MakerFee, TakerFee: f.TakerFee, Buyer: f.Buyer, Seller: f.Seller,
		}
	}
	cells := make([]StateCell, len(req.Cells))
	for i, c := range req.Cells {
		cells[i] = StateCell{Owner: c.Owner, Denom: c.Denom, OldBalance: c.OldBalance, DeltaIn: c.DeltaIn, DeltaOut: c.DeltaOut}
	}

	batch := CanonicalTradeBatch{
		Orders:     orders,
		Fills:      fills,
		BidPrice:   req.BidPrice,
		AskPrice:   req.AskPrice,
		FillPrice:  req.FillPrice,
		MakerIsBid: req.MakerIsBid,
		Conservation: ConservationFill{
			Price: req.Conservation.Price, Qty: req.Conservation.Qty,
			MakerFee: req.Conservation.MakerFee, TakerFee: req.Conservation.TakerFee,
			BuyerIsMaker:             req.Conservation.BuyerIsMaker,
			BuyerReservedQuoteBefore: req.Conservation.BuyerReservedQuoteBefore,
			SellerReservedBaseBefore: req.Conservation.SellerReservedBaseBefore,
		},
		Cells:               cells,
		DepositsRoot:        req.DepositsRoot,
		WithdrawalsRoot:     req.WithdrawalsRoot,
		NullifiersRoot:      req.NullifiersRoot,
		WithdrawOutputsRoot: req.WithdrawOutputsRoot,
	}

	// Default the empty core-root sentinels when the caller omits them (trade-only
	// batch), so a minimal request still produces a valid 8-input vector.
	def := DefaultCanonicalTradeBatch()
	if batch.DepositsRoot == "" {
		batch.DepositsRoot = def.DepositsRoot
	}
	if batch.WithdrawalsRoot == "" {
		batch.WithdrawalsRoot = def.WithdrawalsRoot
	}
	if batch.NullifiersRoot == "" {
		batch.NullifiersRoot = def.NullifiersRoot
	}
	if batch.WithdrawOutputsRoot == "" {
		batch.WithdrawOutputsRoot = def.WithdrawOutputsRoot
	}
	return batch, nil
}
