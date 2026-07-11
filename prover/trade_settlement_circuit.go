package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// ZK-T09 — the final unified trade circuit whose keys (pk/vk) are generated and
// published under vkId gazk-trade-v1.
//
// TradeSettlementCircuitV1 composes the trade constraint families built as
// prototypes in ZK-T04..T08 over the canonical single-fill batch (2 orders + 1
// fill), exposing the LOCKED 8 public inputs (zk_trade_io.md §6):
//
//	[0] oldStateRoot   [1] newStateRoot
//	[2] depositsRoot   [3] withdrawalsRoot   [4] nullifiersRoot   [5] withdrawOutputsRoot
//	[6] tradesRoot     [7] ordersRoot
//
// Constraints:
//   - ZK-T04 price crossing (applyPriceCrossingConstraints) on the fill.
//   - ZK-T05 conservation + non-negative (applyConservationConstraints) on the fill.
//   - ZK-T07 tradesRoot/ordersRoot binding (MiMC fold of the leaves) == [6]/[7].
//     The order leaves carry orderHash + orderNullifier (ZK-T03/T06), so the root
//     transitively commits them.
//   - ZK-T08 flat state-root transition over buyer/seller/fee cells == [0]/[1].
//   - [2..5] are bound as public inputs (empty sentinels for a trade-only batch).
//
// MVP note: the sub-constraint families operate on their own witness copies of
// the canonical trade; the builder produces a self-consistent witness. Full
// cross-witness equality (tying the raw price/qty in conservation to the hashed
// leaf in the root) is a later hardening; ZK-T09's deliverable is the KEY
// infrastructure (deterministic setup, persisted pk/vk, vkId, vk export, real
// on/off-chain verify), which is what this enables.
type TradeSettlementCircuitV1 struct {
	// ZK-T04 price crossing.
	BidPrice   frontend.Variable
	AskPrice   frontend.Variable
	FillPrice  frontend.Variable
	MakerIsBid frontend.Variable

	// ZK-T05 conservation (nested, all private).
	Cons ConservationCircuitV1

	// ZK-T07 root binding.
	OrdersDomainField frontend.Variable
	TradesDomainField frontend.Variable
	Orders            [protoOrderCount]orderLeafVars
	Fills             [protoFillCount]fillLeafVars

	// ZK-T08 state transition.
	StateDomainField frontend.Variable
	Cells            [maxStateCells]stateCellVars

	// LOCKED 8 public inputs.
	OldStateRoot        frontend.Variable `gnark:",public"`
	NewStateRoot        frontend.Variable `gnark:",public"`
	DepositsRoot        frontend.Variable `gnark:",public"`
	WithdrawalsRoot     frontend.Variable `gnark:",public"`
	NullifiersRoot      frontend.Variable `gnark:",public"`
	WithdrawOutputsRoot frontend.Variable `gnark:",public"`
	TradesRoot          frontend.Variable `gnark:",public"`
	OrdersRoot          frontend.Variable `gnark:",public"`
}

func (c *TradeSettlementCircuitV1) Define(api frontend.API) error {
	// ZK-T04 + ZK-T05 on the fill.
	applyPriceCrossingConstraints(api, c.BidPrice, c.AskPrice, c.FillPrice, c.MakerIsBid)
	applyConservationConstraints(api, &c.Cons)

	// ZK-T07 ordersRoot / tradesRoot binding.
	ordersHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	ordersHasher.Write(c.OrdersDomainField)
	for _, o := range c.Orders {
		ordersHasher.Write(o.OrderHash, o.Owner, o.Nullifier, o.Side, o.Price, o.Qty, o.Remaining, o.Filled)
	}
	api.AssertIsEqual(ordersHasher.Sum(), c.OrdersRoot)

	tradesHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	tradesHasher.Write(c.TradesDomainField)
	for _, f := range c.Fills {
		tradesHasher.Write(f.TradeID, f.Market, f.MakerOrderHash, f.TakerOrderHash, f.Price, f.Qty, f.MakerFee, f.TakerFee, f.Buyer, f.Seller)
	}
	api.AssertIsEqual(tradesHasher.Sum(), c.TradesRoot)

	// ZK-T08 state-root transition.
	oldHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	oldHasher.Write(c.StateDomainField)
	for _, cell := range c.Cells {
		oldHasher.Write(cell.OwnerField, cell.DenomField, cell.OldBalance)
	}
	api.AssertIsEqual(oldHasher.Sum(), c.OldStateRoot)

	for _, cell := range c.Cells {
		api.ToBinary(cell.OldBalance, AmountRangeBits)
		api.ToBinary(cell.DeltaIn, AmountRangeBits)
		api.ToBinary(cell.DeltaOut, AmountRangeBits)
		computed := api.Sub(api.Add(cell.OldBalance, cell.DeltaIn), cell.DeltaOut)
		api.AssertIsEqual(cell.NewBalance, computed)
		api.ToBinary(cell.NewBalance, AmountRangeBits)
		api.AssertIsLessOrEqual(cell.DeltaOut, api.Add(cell.OldBalance, cell.DeltaIn))
	}

	newHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	newHasher.Write(c.StateDomainField)
	for _, cell := range c.Cells {
		newHasher.Write(cell.OwnerField, cell.DenomField, cell.NewBalance)
	}
	api.AssertIsEqual(newHasher.Sum(), c.NewStateRoot)

	// [2..5] are bound as public inputs (empty sentinels for a trade-only batch).
	// No internal constraint: the verifier checks them against the expected core
	// roots supplied alongside the proof.
	_ = c.DepositsRoot
	_ = c.WithdrawalsRoot
	_ = c.NullifiersRoot
	_ = c.WithdrawOutputsRoot

	return nil
}

// TradeCircuitEngine holds the compiled circuit + persisted Groth16 keys for the
// unified trade circuit (ZK-T09). Keys load from GAZK_KEY_DIR when present,
// otherwise a fresh (MVP, untrusted) setup is generated.
type TradeCircuitEngine struct {
	ccs        constraint.ConstraintSystem
	provingKey groth16.ProvingKey
	verifyKey  groth16.VerifyingKey
}

// NewTradeCircuitEngine compiles TradeSettlementCircuitV1 and loads-or-sets-up
// its keys under vkId gazk-trade-v1.
func NewTradeCircuitEngine() (*TradeCircuitEngine, error) {
	var circuit TradeSettlementCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compile trade settlement circuit v1: %w", err)
	}
	provingKey, verifyKey, err := loadOrSetupGroth16Keys(ccs, configuredKeyDir(), TradeVerificationKeyID)
	if err != nil {
		return nil, fmt.Errorf("load/setup trade circuit keys: %w", err)
	}
	return &TradeCircuitEngine{ccs: ccs, provingKey: provingKey, verifyKey: verifyKey}, nil
}

// VerifyingKey returns the trade verifying key (for VerifierArtifact export).
func (e *TradeCircuitEngine) VerifyingKey() groth16.VerifyingKey { return e.verifyKey }

// Prove builds a Groth16 proof for the assembled canonical-trade witness.
func (e *TradeCircuitEngine) Prove(input TradeSettlementCircuitV1Input) (string, error) {
	witness, err := frontend.NewWitness(&input.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build trade settlement witness: %w", err)
	}
	proof, err := groth16.Prove(e.ccs, e.provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove trade settlement circuit v1: %w", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize trade settlement proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

// VerifyPublicInputs verifies a proof against the 8 public inputs (0x hex, locked
// order). This is the real Groth16 verification wired into VerifyTrade (ZK-T09
// replaces the ZK-T02 stub body while keeping the same signature).
func (e *TradeCircuitEngine) VerifyPublicInputs(proofHex string, publicInputs []string) error {
	if len(publicInputs) != TradePublicInputCount {
		return fmt.Errorf("%w: expected %d public inputs, got %d", ErrTradeProofRejected, TradePublicInputCount, len(publicInputs))
	}
	proofBytes, err := decodeProofHex(proofHex)
	if err != nil {
		return err
	}
	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("%w: cannot deserialize trade proof: %v", ErrTradeProofRejected, err)
	}

	fields := make([]*big.Int, TradePublicInputCount)
	for i, in := range publicInputs {
		f, perr := parse0xFieldBigInt(in, fmt.Sprintf("publicInputs[%d]", i))
		if perr != nil {
			return perr
		}
		fields[i] = f
	}

	publicAssignment := TradeSettlementCircuitV1{
		OldStateRoot:        fields[0],
		NewStateRoot:        fields[1],
		DepositsRoot:        fields[2],
		WithdrawalsRoot:     fields[3],
		NullifiersRoot:      fields[4],
		WithdrawOutputsRoot: fields[5],
		TradesRoot:          fields[6],
		OrdersRoot:          fields[7],
	}
	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build trade public witness: %w", err)
	}
	if err := groth16.Verify(proof, e.verifyKey, publicWitness); err != nil {
		return fmt.Errorf("%w: Groth16 trade verification failed: %v", ErrTradeProofRejected, err)
	}
	return nil
}
