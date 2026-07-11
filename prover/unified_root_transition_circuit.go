package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// ZK-T08 — Unified root transition.
//
// A batch may contain deposits + withdrawals + trades at once (reuse pipeline).
// This proves oldStateRoot -> newStateRoot is correct when ALL three op types are
// applied to the state, so every kind of transaction reduces to one verifiable
// root transition feeding a single newStateRoot.
//
// State model (MVP, matching the existing gazk SettlementCircuitV1 which commits
// balances flatly, "not a Merkle tree yet"). The state root is a FLAT MiMC
// commitment over a fixed set of account-balance CELLS (owner, denom, balance):
//
//	stateRoot = MiMC( domainField, [ownerField_i, denomField_i, balance_i]... )
//
// Fixed arity maxStateCells with no-op padding (plan: "cố định số account tối
// đa/batch và pad"). Per cell the net delta aggregates EVERY op touching it —
// deposit (DeltaIn), withdraw (DeltaOut), and trade credits/debits (ZK-T05
// deltas). The circuit does not care which op produced the delta; it proves:
//
//	oldStateRoot == fold(oldBalance cells)
//	newBalance_i == oldBalance_i + DeltaIn_i - DeltaOut_i   (per cell)
//	newBalance_i >= 0                                        (range-check)
//	newStateRoot == fold(newBalance cells)
//
// The empty-trade case is just a batch whose trade cells have zero delta
// (deposit/withdraw only), and vice-versa — both handled by the same circuit.
//
// A real sparse Merkle tree with per-account inclusion proofs (Poseidon SMT) and
// byte-exact agreement with P3's off-chain root is deferred (same limitation the
// core circuit still has); ZK-T08a builds the array-based Merkle transition on
// top of this. Prototype: NOT wired into /prove yet.
const (
	// maxStateCells is the fixed number of (owner, denom) balance cells the
	// prototype transition circuit binds; unused slots are padded no-op.
	maxStateCells = 4

	stateRootDomainTagV1 = "zkdex/batch/stateRoot/v1"
)

type stateCellVars struct {
	OwnerField frontend.Variable
	DenomField frontend.Variable
	OldBalance frontend.Variable
	DeltaIn    frontend.Variable
	DeltaOut   frontend.Variable
	NewBalance frontend.Variable
}

type UnifiedRootTransitionCircuitV1 struct {
	DomainField frontend.Variable

	Cells [maxStateCells]stateCellVars

	OldStateRoot frontend.Variable `gnark:",public"`
	NewStateRoot frontend.Variable `gnark:",public"`
}

func (c *UnifiedRootTransitionCircuitV1) Define(api frontend.API) error {
	// old root = fold of old balances.
	oldHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	oldHasher.Write(c.DomainField)
	for _, cell := range c.Cells {
		oldHasher.Write(cell.OwnerField, cell.DenomField, cell.OldBalance)
	}
	api.AssertIsEqual(oldHasher.Sum(), c.OldStateRoot)

	// per-cell transition + non-negativity.
	for _, cell := range c.Cells {
		api.ToBinary(cell.OldBalance, AmountRangeBits)
		api.ToBinary(cell.DeltaIn, AmountRangeBits)
		api.ToBinary(cell.DeltaOut, AmountRangeBits)

		// newBalance = oldBalance + DeltaIn - DeltaOut.
		computed := api.Sub(api.Add(cell.OldBalance, cell.DeltaIn), cell.DeltaOut)
		api.AssertIsEqual(cell.NewBalance, computed)

		// non-negative: a negative result would underflow to a ~254-bit field
		// element and fail this 100-bit range-check. Explicit compare for clarity.
		api.ToBinary(cell.NewBalance, AmountRangeBits)
		api.AssertIsLessOrEqual(cell.DeltaOut, api.Add(cell.OldBalance, cell.DeltaIn))
	}

	// new root = fold of new balances.
	newHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	newHasher.Write(c.DomainField)
	for _, cell := range c.Cells {
		newHasher.Write(cell.OwnerField, cell.DenomField, cell.NewBalance)
	}
	api.AssertIsEqual(newHasher.Sum(), c.NewStateRoot)

	return nil
}

// StateCell is one (owner, denom) balance cell and its aggregated batch delta.
// DeltaIn = deposits + trade credits; DeltaOut = withdrawals + trade debits.
type StateCell struct {
	Owner      string
	Denom      string
	OldBalance string
	DeltaIn    string
	DeltaOut   string
}

type UnifiedRootTransitionCircuitV1Input struct {
	circuit      UnifiedRootTransitionCircuitV1
	OldStateRoot string
	NewStateRoot string
}

// BuildUnifiedRootTransitionCircuitV1Input maps up to maxStateCells cells into the
// witness (padding the rest no-op) and computes old/new state roots.
func BuildUnifiedRootTransitionCircuitV1Input(cells []StateCell) (UnifiedRootTransitionCircuitV1Input, error) {
	if len(cells) > maxStateCells {
		return UnifiedRootTransitionCircuitV1Input{}, fmt.Errorf("at most %d cells, got %d", maxStateCells, len(cells))
	}

	var circuit UnifiedRootTransitionCircuitV1
	circuit.DomainField = fieldForLeafStringV1(stateRootDomainTagV1)

	oldFields := make([]*big.Int, 0, maxStateCells*3)
	newFields := make([]*big.Int, 0, maxStateCells*3)

	for i := 0; i < maxStateCells; i++ {
		var (
			ownerField = big.NewInt(0)
			denomField = big.NewInt(0)
			oldBal     = big.NewInt(0)
			deltaIn    = big.NewInt(0)
			deltaOut   = big.NewInt(0)
		)
		if i < len(cells) {
			cell := cells[i]
			ownerField = fieldForLeafStringV1(cell.Owner)
			denomField = fieldForLeafStringV1(cell.Denom)
			var err error
			oldBal, err = parseWholeAmount(cell.OldBalance, "oldBalance")
			if err != nil {
				return UnifiedRootTransitionCircuitV1Input{}, err
			}
			deltaIn, err = parseWholeAmount(cell.DeltaIn, "deltaIn")
			if err != nil {
				return UnifiedRootTransitionCircuitV1Input{}, err
			}
			deltaOut, err = parseWholeAmount(cell.DeltaOut, "deltaOut")
			if err != nil {
				return UnifiedRootTransitionCircuitV1Input{}, err
			}
		}

		newBal := new(big.Int).Sub(new(big.Int).Add(oldBal, deltaIn), deltaOut)
		if newBal.Sign() < 0 {
			return UnifiedRootTransitionCircuitV1Input{}, fmt.Errorf("cell %d: newBalance negative (deltaOut exceeds oldBalance+deltaIn)", i)
		}

		circuit.Cells[i] = stateCellVars{
			OwnerField: ownerField, DenomField: denomField,
			OldBalance: oldBal, DeltaIn: deltaIn, DeltaOut: deltaOut, NewBalance: newBal,
		}
		oldFields = append(oldFields, ownerField, denomField, oldBal)
		newFields = append(newFields, ownerField, denomField, newBal)
	}

	oldRoot := foldStateCells(oldFields)
	newRoot := foldStateCells(newFields)
	circuit.OldStateRoot = oldRoot
	circuit.NewStateRoot = newRoot

	return UnifiedRootTransitionCircuitV1Input{
		circuit:      circuit,
		OldStateRoot: "0x" + fieldBigIntToHex(oldRoot),
		NewStateRoot: "0x" + fieldBigIntToHex(newRoot),
	}, nil
}

// foldStateCells folds the domain field + all cell fields with MiMC, matching the
// circuit's Define exactly.
func foldStateCells(cellFields []*big.Int) *big.Int {
	h := bn254mimc.NewMiMC()
	_, _ = h.Write(bigIntToBN254FieldBytes(fieldForLeafStringV1(stateRootDomainTagV1)))
	for _, f := range cellFields {
		_, _ = h.Write(bigIntToBN254FieldBytes(f))
	}
	return bytesToBN254FieldBigInt(h.Sum(nil))
}

func compileAndSetupUnifiedRootCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit UnifiedRootTransitionCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile unified root transition circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup unified root transition circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

// ProveUnifiedRootTransitionCircuitV1 proves the mixed batch transitions the root
// correctly. It fails if any balance/delta is inconsistent or drives a cell
// negative, or if the public roots do not match the folded cells.
func ProveUnifiedRootTransitionCircuitV1(input UnifiedRootTransitionCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupUnifiedRootCircuit()
	if err != nil {
		return "", err
	}

	witness, err := frontend.NewWitness(&input.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build unified root transition witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove unified root transition circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize unified root transition proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

// TamperNewStateRoot forces a wrong public newStateRoot so tests can prove the
// transition rejects it.
func (in *UnifiedRootTransitionCircuitV1Input) TamperNewStateRoot() {
	in.circuit.NewStateRoot = new(big.Int).Add(in.circuit.NewStateRoot.(*big.Int), big.NewInt(1))
}

// TamperCellBalance rewrites a cell's new balance (keeping roots) so the new-root
// fold no longer matches — the binding must reject.
func (in *UnifiedRootTransitionCircuitV1Input) TamperCellBalance(cellIdx int, newBalance int64) {
	in.circuit.Cells[cellIdx].NewBalance = big.NewInt(newBalance)
}
