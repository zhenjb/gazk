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

	// Core [2..5] sentinels (trade-only batch → empty core roots).
	DepositsRoot        string
	WithdrawalsRoot     string
	NullifiersRoot      string
	WithdrawOutputsRoot string
}

// DefaultCanonicalTradeBatch returns the alice/bob single-fill batch consistent
// across all sub-constraints (price 100, qty 20, fees 10/20).
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

	// ZK-T07 root binding leaves.
	circuit.OrdersDomainField = fieldForLeafStringV1(OrdersRootDomainTagV1)
	circuit.TradesDomainField = fieldForLeafStringV1(TradesRootDomainTagV1)
	sorted := sortedOrders(batch.Orders)
	for i, o := range sorted {
		fields, ferr := orderLeafFieldsV1(o)
		if ferr != nil {
			return TradeSettlementCircuitV1Input{}, ferr
		}
		circuit.Orders[i] = orderLeafVars{
			OrderHash: fields[0], Owner: fields[1], Nullifier: fields[2], Side: fields[3],
			Price: fields[4], Qty: fields[5], Remaining: fields[6], Filled: fields[7],
		}
	}
	for i, f := range batch.Fills {
		fields := fillLeafFieldsV1(f)
		circuit.Fills[i] = fillLeafVars{
			TradeID: fields[0], Market: fields[1], MakerOrderHash: fields[2], TakerOrderHash: fields[3],
			Price: fields[4], Qty: fields[5], MakerFee: fields[6], TakerFee: fields[7], Buyer: fields[8], Seller: fields[9],
		}
	}
	ordersRoot, ordersHex, err := OrdersRootV1Field(batch.Orders)
	if err != nil {
		return TradeSettlementCircuitV1Input{}, err
	}
	tradesRoot, tradesHex := TradesRootV1Field(batch.Fills)
	circuit.OrdersRoot = ordersRoot
	circuit.TradesRoot = tradesRoot

	// ZK-T08 transition cells.
	circuit.StateDomainField = fieldForLeafStringV1(stateRootDomainTagV1)
	oldFields := make([]*big.Int, 0, maxStateCells*3)
	newFields := make([]*big.Int, 0, maxStateCells*3)
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
		oldFields = append(oldFields, ownerField, denomField, oldBal)
		newFields = append(newFields, ownerField, denomField, newBal)
	}
	oldStateRoot := foldStateCells(oldFields)
	newStateRoot := foldStateCells(newFields)
	circuit.OldStateRoot = oldStateRoot
	circuit.NewStateRoot = newStateRoot

	// Core [2..5] sentinels.
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
	circuit.DepositsRoot = depositsRoot
	circuit.WithdrawalsRoot = withdrawalsRoot
	circuit.NullifiersRoot = nullifiersRoot
	circuit.WithdrawOutputsRoot = withdrawOutputsRoot

	publicInputs := []string{
		"0x" + fieldBigIntToHex(oldStateRoot),
		"0x" + fieldBigIntToHex(newStateRoot),
		batch.DepositsRoot,
		batch.WithdrawalsRoot,
		batch.NullifiersRoot,
		batch.WithdrawOutputsRoot,
		tradesHex,
		ordersHex,
	}

	return TradeSettlementCircuitV1Input{circuit: circuit, PublicInputs: publicInputs}, nil
}
