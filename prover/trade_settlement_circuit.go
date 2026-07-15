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
)

// ZK-T09 / TRD-A1 — the final unified trade circuit whose keys (pk/vk) are
// generated and published under vkId gazk-trade-v1.
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
//   - ZK-T08 per-cell balance transition over buyer/seller/fee cells: newBalance ==
//     oldBalance + deltaIn - deltaOut, all non-negative (range-checked), no over-debit.
//   - ALL 8 public roots [0..7] are BOUND via api.ToBinary — the ZK-T11 core pattern.
//
// TRD-A1 (v0 root binding). PREVIOUSLY this circuit RECOMPUTED tradesRoot/ordersRoot
// and the state roots in-circuit with MiMC and asserted equality with the public
// inputs. That made the proof commit the FIELD-NATIVE v1 (MiMC) roots, which differ
// from the v0 (SHA-256) roots P3/BE/chain carry on the wire (zk_trade_io.md §5/§10) —
// so a real gazk proof could never reconcile with the chain's derivePublicInputs.
// It now BINDS the v0 wire roots as opaque public inputs (api.ToBinary, exactly like
// core [2..5] and ZK-T11): the builder fills [6]/[7] from OrdersRootV0/TradesRootV0
// (byte-exact P3) and [0]/[1] from P3's v0 state roots. Tamper-evidence is the same
// as core: the verifier (chain / BE gate) INDEPENDENTLY re-derives every root from the
// submitted orders[]/fills[] via v0 SHA-256; tamper one field -> the re-derived root
// differs -> the proof (bound to the original) fails verification. Because ordersRoot
// commits BOTH order nullifiers (maker+taker, ZK-T06), the two-per-fill records
// (AGR-2b) are both transitively bound — the chain cannot mark a fabricated nullifier.
//
// MVP note: binding the roots opaquely (not re-hashing leaves in-circuit) means the
// price/conservation/transition witness is not yet tied in-circuit to the specific
// leaves behind [6]/[7]; that full cross-witness equality (SHA-256 leaf binding) is a
// later hardening, deferred exactly as the core state root is. The verifier's
// independent v0 re-derivation is what carries soundness at the MVP stage.
type TradeSettlementCircuitV1 struct {
	// ZK-T04 price crossing.
	BidPrice   frontend.Variable
	AskPrice   frontend.Variable
	FillPrice  frontend.Variable
	MakerIsBid frontend.Variable

	// ZK-T05 conservation (nested, all private).
	Cons ConservationCircuitV1

	// ZK-T08 state transition (per-cell delta math; roots bound as v0 below).
	Cells [maxStateCells]stateCellVars

	// LOCKED 8 public inputs (v0 wire roots — bound opaquely, TRD-A1).
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

	// ZK-T08 per-cell balance transition: value is conserved cell-by-cell and no
	// balance goes negative. This stays a real economic constraint on the witness;
	// the resulting state ROOTS [0]/[1] are bound below as v0 wire values (the chain
	// re-derives them), rather than recomputed here in v1 MiMC (TRD-A1).
	for _, cell := range c.Cells {
		api.ToBinary(cell.OldBalance, AmountRangeBits)
		api.ToBinary(cell.DeltaIn, AmountRangeBits)
		api.ToBinary(cell.DeltaOut, AmountRangeBits)
		computed := api.Sub(api.Add(cell.OldBalance, cell.DeltaIn), cell.DeltaOut)
		api.AssertIsEqual(cell.NewBalance, computed)
		api.ToBinary(cell.NewBalance, AmountRangeBits)
		api.AssertIsLessOrEqual(cell.DeltaOut, api.Add(cell.OldBalance, cell.DeltaIn))
	}

	// TRD-A1: BIND all 8 public roots as v0 wire values. A public input with no
	// constraint is dropped by the frontend (gnark), leaving it uncommitted — a real
	// false-accept surface found in ZK-T11. Range-checking (ToBinary) each forces it
	// into the constraint system so the proof commits to EXACTLY these 8 root values;
	// the chain then verifies its independently-derived v0 roots against them.
	api.ToBinary(c.OldStateRoot)
	api.ToBinary(c.NewStateRoot)
	api.ToBinary(c.DepositsRoot)
	api.ToBinary(c.WithdrawalsRoot)
	api.ToBinary(c.NullifiersRoot)
	api.ToBinary(c.WithdrawOutputsRoot)
	api.ToBinary(c.TradesRoot)
	api.ToBinary(c.OrdersRoot)

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

// NewTradeCircuitEngine compiles TradeSettlementCircuitV1 and loads-or-sets-up its
// keys under vkId gazk-trade-v1. Persisted keys are guarded by a circuit fingerprint
// (loadOrSetupTradeKeys): after any circuit change the stale key is regenerated
// automatically rather than loaded silently (TRD-A2).
func NewTradeCircuitEngine() (*TradeCircuitEngine, error) {
	var circuit TradeSettlementCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compile trade settlement circuit v1: %w", err)
	}
	provingKey, verifyKey, err := loadOrSetupTradeKeys(ccs, configuredKeyDir(), TradeVerificationKeyID)
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
