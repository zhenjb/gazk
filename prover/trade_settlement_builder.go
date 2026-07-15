package prover

import (
	"fmt"
	"math/big"
)

// TradeSettlementCircuitV1Input is the assembled witness + the 8 public inputs
// (0x hex, locked order) for the unified trade circuit.
type TradeSettlementCircuitV1Input struct {
	circuit      TradeSettlementCircuitV1
	PublicInputs []string
}

// CanonicalTradeBatch is the canonical alice/bob trade used to exercise the
// unified circuit and generate/verify keys.
type CanonicalTradeBatch struct {
	Orders []OrderLeaf
	Fills  []FillLeaf

	// Price crossing.
	BidPrice   string
	AskPrice   string
	FillPrice  string
	MakerIsBid bool

	// Conservation fill economics.
	Conservation ConservationFill

	// State-transition cells (buyer/seller/fee), padded to maxStateCells.
	Cells []StateCell

	// v0 state roots [0]/[1] (P3 wire values; bound opaquely — TRD-A1). gazk cannot
	// re-derive P3's state root, so the caller supplies it.
	OldStateRoot string
	NewStateRoot string

	// v0 trade roots [6]/[7] (P3 wire values). When supplied, gazk binds them
	// verbatim — P3 is the authoritative root deriver and owns the exact leaf order
	// (sort by Sequence, which the witness does not carry). When OMITTED (standalone
	// canonical test), gazk self-derives them byte-exact via TradesRootV0/OrdersRootV0.
	TradesRoot string
	OrdersRoot string

	// Core [2..5] sentinels (trade-only batch → empty core roots).
	DepositsRoot        string
	WithdrawalsRoot     string
	NullifiersRoot      string
	WithdrawOutputsRoot string
}

// DefaultCanonicalTradeBatch returns the alice/bob single-fill batch consistent
// across all sub-constraints (price 100, qty 20, fees 10/20). Its state roots are
// pinned to the zk_trade_io.md §8 canonical vector so the standalone circuit test
// reproduces the published wire values byte-exact.
func DefaultCanonicalTradeBatch() CanonicalTradeBatch {
	return CanonicalTradeBatch{
		Orders:     aliceBobTradeOrders(),
		Fills:      aliceBobTradeFills(),
		BidPrice:   "100",
		AskPrice:   "100",
		FillPrice:  "100",
		MakerIsBid: true,
		Conservation: ConservationFill{
			Price: "100", Qty: "20", MakerFee: "10", TakerFee: "20",
			BuyerIsMaker: true, BuyerReservedQuoteBefore: "2010", SellerReservedBaseBefore: "20",
		},
		Cells: []StateCell{
			{Owner: "alice", Denom: "uusdc", OldBalance: "2010", DeltaIn: "0", DeltaOut: "2010"},
			{Owner: "bob", Denom: "uusdc", OldBalance: "0", DeltaIn: "1980", DeltaOut: "0"},
			{Owner: "zkdex/fee-account", Denom: "uusdc", OldBalance: "0", DeltaIn: "30", DeltaOut: "0"},
		},
		// zk_trade_io.md §8 canonical v0 state roots (SHA-256 wire values).
		OldStateRoot:        "0xdc03bee69322b6f860de17cc11d8bee7e5cc41ae22e72d3da1065fe8d13db103",
		NewStateRoot:        "0xc79bc87c5df4b3cf94560d58f19f2b36631b93a60132efd0c61ac8b474069e61",
		DepositsRoot:        "0x" + fieldBigIntToHex(fieldForLeafStringV1("zkdex/empty/deposits")),
		WithdrawalsRoot:     "0x" + fieldBigIntToHex(fieldForLeafStringV1("zkdex/empty/withdrawals")),
		NullifiersRoot:      "0x" + fieldBigIntToHex(fieldForLeafStringV1("zkdex/empty/nullifiers")),
		WithdrawOutputsRoot: "0x" + fieldBigIntToHex(fieldForLeafStringV1("zkdex/empty/withdrawOutputs")),
	}
}

func aliceBobTradeOrders() []OrderLeaf {
	return []OrderLeaf{
		{OrderHash: "0x60ab102de75186520e5bc75fee0b76583567323946d50dddafcd0b55334dbb8a", Owner: "alice", Side: "buy", Price: "100", Qty: "20", Remaining: "0", Filled: true, Sequence: 1},
		{OrderHash: "0xbeeae7ff0bad0b8e19594892537e52e77a17cfd0b6c92ebfe105911c1897749f", Owner: "bob", Side: "sell", Price: "100", Qty: "20", Remaining: "0", Filled: true, Sequence: 2},
	}
}

func aliceBobTradeFills() []FillLeaf {
	return []FillLeaf{{
		TradeID: "0xc0b11f3a4fbf7ca3ba85c2b90a7c4c6337da9001e14dd2b5bf0d149a8c06cd14", Market: "ATOM/USDC",
		MakerOrderHash: "0x60ab102de75186520e5bc75fee0b76583567323946d50dddafcd0b55334dbb8a",
		TakerOrderHash: "0xbeeae7ff0bad0b8e19594892537e52e77a17cfd0b6c92ebfe105911c1897749f",
		Price:          "100", Qty: "20", MakerFee: "10", TakerFee: "20", Buyer: "alice", Seller: "bob",
	}}
}

// BuildTradeSettlementCircuitV1Input assembles a self-consistent witness for the
// unified circuit and the 8 public inputs.
func BuildTradeSettlementCircuitV1Input(batch CanonicalTradeBatch) (TradeSettlementCircuitV1Input, error) {
	if len(batch.Orders) != protoOrderCount || len(batch.Fills) != protoFillCount {
		return TradeSettlementCircuitV1Input{}, fmt.Errorf("canonical batch must be %d orders + %d fill", protoOrderCount, protoFillCount)
	}
	if len(batch.Cells) > maxStateCells {
		return TradeSettlementCircuitV1Input{}, fmt.Errorf("at most %d cells", maxStateCells)
	}

	var circuit TradeSettlementCircuitV1

	// ZK-T04 price crossing.
	priceIn, err := BuildPriceCrossingCircuitV1Input(batch.BidPrice, batch.AskPrice, batch.FillPrice, batch.MakerIsBid)
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	circuit.BidPrice = priceIn.BidPrice
	circuit.AskPrice = priceIn.AskPrice
	circuit.FillPrice = priceIn.FillPrice
	circuit.MakerIsBid = priceIn.MakerIsBid

	// ZK-T05 conservation.
	consIn, err := BuildConservationCircuitV1Input(batch.Conservation)
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	circuit.Cons = conservationAssignment(consIn)

	// TRD-A1: [6]/[7] are the v0 (SHA-256) roots — byte-exact P3 wire (zk_trade_io.md
	// §4/§8), NOT the field-native v1 MiMC fold. A live batch supplies P3's authoritative
	// roots (P3 owns the exact leaf sort order); a standalone canonical batch omits them
	// and gazk self-derives byte-exact. OrdersRootV0 carries the duplicate-nullifier guard.
	ordersHex := batch.OrdersRoot
	if ordersHex == "" {
		ordersHex, err = OrdersRootV0(batch.Orders)
		if err != nil {
			return TradeSettlementCircuitV1Input{}, err
		}
	}
	tradesHex := batch.TradesRoot
	if tradesHex == "" {
		tradesHex = TradesRootV0(batch.Fills)
	}

	// ZK-T08 transition cells (per-cell delta math; roots bound as v0 below).
	for i := 0; i < maxStateCells; i++ {
		ownerField, denomField := big.NewInt(0), big.NewInt(0)
		oldBal, deltaIn, deltaOut := big.NewInt(0), big.NewInt(0), big.NewInt(0)
		if i < len(batch.Cells) {
			cell := batch.Cells[i]
			ownerField = fieldForLeafStringV1(cell.Owner)
			denomField = fieldForLeafStringV1(cell.Denom)
			oldBal, err = parseWholeAmount(cell.OldBalance, "oldBalance")
			if err != nil {
				return TradeSettlementCircuitV1Input{}, err
			}
			deltaIn, err = parseWholeAmount(cell.DeltaIn, "deltaIn")
			if err != nil {
				return TradeSettlementCircuitV1Input{}, err
			}
			deltaOut, err = parseWholeAmount(cell.DeltaOut, "deltaOut")
			if err != nil {
				return TradeSettlementCircuitV1Input{}, err
			}
		}
		newBal := new(big.Int).Sub(new(big.Int).Add(oldBal, deltaIn), deltaOut)
		if newBal.Sign() < 0 {
			return TradeSettlementCircuitV1Input{}, fmt.Errorf("cell %d newBalance negative", i)
		}
		circuit.Cells[i] = stateCellVars{
			OwnerField: ownerField, DenomField: denomField,
			OldBalance: oldBal, DeltaIn: deltaIn, DeltaOut: deltaOut, NewBalance: newBal,
		}
	}

	// [0]/[1] v0 state roots + [2..5] core sentinels: all bound opaquely (ToBinary).
	oldStateRoot, err := parse0xFieldBigInt(batch.OldStateRoot, "oldStateRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	newStateRoot, err := parse0xFieldBigInt(batch.NewStateRoot, "newStateRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	depositsRoot, err := parse0xFieldBigInt(batch.DepositsRoot, "depositsRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	withdrawalsRoot, err := parse0xFieldBigInt(batch.WithdrawalsRoot, "withdrawalsRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	nullifiersRoot, err := parse0xFieldBigInt(batch.NullifiersRoot, "nullifiersRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	withdrawOutputsRoot, err := parse0xFieldBigInt(batch.WithdrawOutputsRoot, "withdrawOutputsRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	tradesRoot, err := parse0xFieldBigInt(tradesHex, "tradesRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	ordersRoot, err := parse0xFieldBigInt(ordersHex, "ordersRoot")
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	circuit.OldStateRoot = oldStateRoot
	circuit.NewStateRoot = newStateRoot
	circuit.DepositsRoot = depositsRoot
	circuit.WithdrawalsRoot = withdrawalsRoot
	circuit.NullifiersRoot = nullifiersRoot
	circuit.WithdrawOutputsRoot = withdrawOutputsRoot
	circuit.TradesRoot = tradesRoot
	circuit.OrdersRoot = ordersRoot

	publicInputs := []string{
		batch.OldStateRoot,
		batch.NewStateRoot,
		batch.DepositsRoot,
		batch.WithdrawalsRoot,
		batch.NullifiersRoot,
		batch.WithdrawOutputsRoot,
		tradesHex,
		ordersHex,
	}

	return TradeSettlementCircuitV1Input{circuit: circuit, PublicInputs: publicInputs}, nil
}
