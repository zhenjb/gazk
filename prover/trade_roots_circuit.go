package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// ZK-T07 in-circuit root binding.
//
// TradeRootBindingCircuitV1 recomputes ordersRoot/tradesRoot from the field-
// mapped leaves (MiMC fold, same leaf order as trade_roots.go) and AssertIsEqual
// with the public [7]/[6]. Prototype arity: 2 orders + 1 fill (the alice/bob
// canonical batch); ZK-T08a/T09 generalize to N leaves with padding.
//
// The leaf field VALUES are mapped out-of-circuit (fieldForLeafStringV1) exactly
// like OrdersRootV1Field/TradesRootV1Field, so the in-circuit fold equals the
// helper root. Tamper any leaf field -> different mapped value -> different root
// -> AssertIsEqual fails.

const (
	protoOrderCount = 2
	protoFillCount  = 1
)

type orderLeafVars struct {
	OrderHash frontend.Variable
	Owner     frontend.Variable
	Nullifier frontend.Variable
	Side      frontend.Variable
	Price     frontend.Variable
	Qty       frontend.Variable
	Remaining frontend.Variable
	Filled    frontend.Variable
}

type fillLeafVars struct {
	TradeID        frontend.Variable
	Market         frontend.Variable
	MakerOrderHash frontend.Variable
	TakerOrderHash frontend.Variable
	Price          frontend.Variable
	Qty            frontend.Variable
	MakerFee       frontend.Variable
	TakerFee       frontend.Variable
	Buyer          frontend.Variable
	Seller         frontend.Variable
}

type TradeRootBindingCircuitV1 struct {
	OrdersDomainField frontend.Variable
	TradesDomainField frontend.Variable

	Orders [protoOrderCount]orderLeafVars
	Fills  [protoFillCount]fillLeafVars

	ExpectedOrdersRoot frontend.Variable `gnark:",public"`
	ExpectedTradesRoot frontend.Variable `gnark:",public"`
}

func (c *TradeRootBindingCircuitV1) Define(api frontend.API) error {
	ordersHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	ordersHasher.Write(c.OrdersDomainField)
	for _, o := range c.Orders {
		ordersHasher.Write(o.OrderHash, o.Owner, o.Nullifier, o.Side, o.Price, o.Qty, o.Remaining, o.Filled)
	}
	api.AssertIsEqual(ordersHasher.Sum(), c.ExpectedOrdersRoot)

	tradesHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	tradesHasher.Write(c.TradesDomainField)
	for _, f := range c.Fills {
		tradesHasher.Write(f.TradeID, f.Market, f.MakerOrderHash, f.TakerOrderHash, f.Price, f.Qty, f.MakerFee, f.TakerFee, f.Buyer, f.Seller)
	}
	api.AssertIsEqual(tradesHasher.Sum(), c.ExpectedTradesRoot)

	return nil
}

// TradeRootBindingCircuitV1Input is the assembled witness.
type TradeRootBindingCircuitV1Input struct {
	circuit            TradeRootBindingCircuitV1
	ExpectedOrdersRoot string
	ExpectedTradesRoot string
}

// BuildTradeRootBindingCircuitV1Input maps the alice/bob-shaped batch (exactly 2
// orders + 1 fill) into the circuit witness and computes the expected v1 roots.
func BuildTradeRootBindingCircuitV1Input(orders []OrderLeaf, fills []FillLeaf) (TradeRootBindingCircuitV1Input, error) {
	if len(orders) != protoOrderCount || len(fills) != protoFillCount {
		return TradeRootBindingCircuitV1Input{}, fmt.Errorf("prototype arity is %d orders + %d fill, got %d + %d", protoOrderCount, protoFillCount, len(orders), len(fills))
	}

	sorted := sortedOrders(orders)

	var circuit TradeRootBindingCircuitV1
	circuit.OrdersDomainField = fieldForLeafStringV1(OrdersRootDomainTagV1)
	circuit.TradesDomainField = fieldForLeafStringV1(TradesRootDomainTagV1)

	for i, o := range sorted {
		fields, err := orderLeafFieldsV1(o)
		if err != nil {
			return TradeRootBindingCircuitV1Input{}, err
		}
		circuit.Orders[i] = orderLeafVars{
			OrderHash: fields[0], Owner: fields[1], Nullifier: fields[2], Side: fields[3],
			Price: fields[4], Qty: fields[5], Remaining: fields[6], Filled: fields[7],
		}
	}
	for i, f := range fills {
		fields := fillLeafFieldsV1(f)
		circuit.Fills[i] = fillLeafVars{
			TradeID: fields[0], Market: fields[1], MakerOrderHash: fields[2], TakerOrderHash: fields[3],
			Price: fields[4], Qty: fields[5], MakerFee: fields[6], TakerFee: fields[7], Buyer: fields[8], Seller: fields[9],
		}
	}

	ordersRoot, ordersHex, err := OrdersRootV1Field(orders)
	if err != nil {
		return TradeRootBindingCircuitV1Input{}, err
	}
	tradesRoot, tradesHex := TradesRootV1Field(fills)
	circuit.ExpectedOrdersRoot = ordersRoot
	circuit.ExpectedTradesRoot = tradesRoot

	return TradeRootBindingCircuitV1Input{
		circuit:            circuit,
		ExpectedOrdersRoot: ordersHex,
		ExpectedTradesRoot: tradesHex,
	}, nil
}

func compileAndSetupTradeRootCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit TradeRootBindingCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile trade root binding circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup trade root binding circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

// ProveTradeRootBindingCircuitV1 proves the leaves fold to the expected roots. It
// fails if any leaf field was tampered (root mismatch).
func ProveTradeRootBindingCircuitV1(input TradeRootBindingCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupTradeRootCircuit()
	if err != nil {
		return "", err
	}

	witness, err := frontend.NewWitness(&input.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build trade root binding witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove trade root binding circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize trade root binding proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

// TamperFillPrice rewrites the first fill's price leaf (keeping the expected
// roots) so the recomputed tradesRoot no longer matches — the binding must then
// reject. Used by the tamper test.
func (in *TradeRootBindingCircuitV1Input) TamperFillPrice(newPrice string) {
	in.circuit.Fills[0].Price = fieldForLeafStringV1(newPrice)
}
