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

// ZK-T08a — Multi-withdrawal aggregation.
//
// The v1 settlement circuit proves EXACTLY ONE withdrawal/proof: it binds the
// nullifier to a single account nonce and rejects len(withdrawals)!=1. So N
// withdrawals need N sequential proofs, and the sequencer once produced a real
// "nullifier mismatch" when it accidentally merged two withdrawals into one
// proof (both bound to the same single nonce). This circuit lifts that to
// ARRAY-BASED, N ops/proof: one proof settles up to maxWithdrawalsPerProof
// withdrawals of one account, each with its OWN nonce.
//
// Per active withdrawal i (nonce-vector — the fix):
//
//	nullifier_i = MiMC(secretField, nonceField_i)         (field-native, ZK-T06 template)
//	AssertIsEqual(nullifier_i, ExpectedNullifier_i)
//
// so two withdrawals never share a nonce/nullifier. Slots are fixed-size with
// no-op padding (Active=0, Amount=0) for a constant constraint count. The account
// balance transitions old -> new by the sum of withdrawn amounts (reusing the
// ZK-T08 flat single-account root), non-negative, and all expected nullifiers are
// folded into nullifiersRoot (public [4]).
//
// v0/v1: the wire nullifier is core NullifierFor = SHA256("zkdex/nullifier/v0"|
// secret|nonce); the in-circuit value is the field-native MiMC (existing
// NullifierCircuitV1). They reconcile at the lockstep migration (zk_trade_io §10),
// exactly like ZK-T06. Prototype: NOT wired into /prove yet.
const (
	maxWithdrawalsPerProof = 4

	nullifiersRootDomainTagV1 = "zkdex/batch/nullifiersRoot/v1"
)

type withdrawalSlotVars struct {
	Active            frontend.Variable // boolean: 1 = real withdrawal, 0 = padding
	NonceField        frontend.Variable
	Amount            frontend.Variable
	ExpectedNullifier frontend.Variable
}

type MultiWithdrawalCircuitV1 struct {
	StateDomainField     frontend.Variable
	NullifierDomainField frontend.Variable
	OwnerField           frontend.Variable
	SecretField          frontend.Variable
	OldBalance           frontend.Variable
	NewBalance           frontend.Variable

	Withdrawals [maxWithdrawalsPerProof]withdrawalSlotVars

	OldStateRoot   frontend.Variable `gnark:",public"`
	NewStateRoot   frontend.Variable `gnark:",public"`
	NullifiersRoot frontend.Variable `gnark:",public"`
}

func (c *MultiWithdrawalCircuitV1) Define(api frontend.API) error {
	// old state root = flat single-account commitment (ZK-T08 model).
	oldHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	oldHasher.Write(c.StateDomainField, c.OwnerField, c.OldBalance)
	api.AssertIsEqual(oldHasher.Sum(), c.OldStateRoot)

	total := frontend.Variable(0)
	for i := range c.Withdrawals {
		w := c.Withdrawals[i]
		api.AssertIsBoolean(w.Active)

		// Padding slots must carry amount 0 (no balance effect).
		api.AssertIsEqual(api.Mul(w.Amount, api.Sub(1, w.Active)), 0)
		api.ToBinary(w.Amount, AmountRangeBits)

		// Per-withdrawal nullifier = MiMC(secret, nonce_i). Gated so inactive
		// slots pass trivially: active => computed must equal expected.
		nullHasher, herr := stdmimc.NewMiMC(api)
		if herr != nil {
			return herr
		}
		nullHasher.Write(c.SecretField, w.NonceField)
		computed := nullHasher.Sum()
		api.AssertIsEqual(api.Select(w.Active, computed, w.ExpectedNullifier), w.ExpectedNullifier)

		// Nonces strictly increasing among active slots (active-first). When slot
		// i is active, nonce_i >= nonce_{i-1} + 1. Gated slack range-check.
		if i > 0 {
			prev := c.Withdrawals[i-1].NonceField
			slack := api.Sub(w.NonceField, prev, 1) // nonce_i - nonce_{i-1} - 1
			gated := api.Select(w.Active, slack, 0)
			api.ToBinary(gated, AmountRangeBits) // >= 0 when active
		}

		total = api.Add(total, w.Amount)
	}

	// Balance transition: newBalance = oldBalance - Σ amount_i, non-negative.
	api.AssertIsEqual(c.NewBalance, api.Sub(c.OldBalance, total))
	api.ToBinary(c.NewBalance, AmountRangeBits)

	// new state root.
	newHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	newHasher.Write(c.StateDomainField, c.OwnerField, c.NewBalance)
	api.AssertIsEqual(newHasher.Sum(), c.NewStateRoot)

	// nullifiersRoot = fold of all slots' expected nullifiers (public [4]).
	nullRootHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	nullRootHasher.Write(c.NullifierDomainField)
	for i := range c.Withdrawals {
		nullRootHasher.Write(c.Withdrawals[i].ExpectedNullifier)
	}
	api.AssertIsEqual(nullRootHasher.Sum(), c.NullifiersRoot)

	return nil
}

// WithdrawalOp is one withdrawal in a multi-withdrawal batch (all for one owner).
type WithdrawalOp struct {
	Nonce  string
	Amount string
}

type MultiWithdrawalCircuitV1Input struct {
	circuit        MultiWithdrawalCircuitV1
	OldStateRoot   string
	NewStateRoot   string
	NullifiersRoot string
}

// BuildMultiWithdrawalCircuitV1Input assembles the witness for up to
// maxWithdrawalsPerProof withdrawals of one account (owner/secret), padding the
// rest no-op. Withdrawals must be given in strictly increasing nonce order.
func BuildMultiWithdrawalCircuitV1Input(owner, userSecret, oldBalance string, ops []WithdrawalOp) (MultiWithdrawalCircuitV1Input, error) {
	if len(ops) == 0 {
		return MultiWithdrawalCircuitV1Input{}, fmt.Errorf("at least one withdrawal required")
	}
	if len(ops) > maxWithdrawalsPerProof {
		return MultiWithdrawalCircuitV1Input{}, fmt.Errorf("at most %d withdrawals/proof, got %d", maxWithdrawalsPerProof, len(ops))
	}

	ownerField := fieldForLeafStringV1(owner)
	secretField, err := SecretFieldForV1(userSecret)
	if err != nil {
		return MultiWithdrawalCircuitV1Input{}, err
	}
	oldBal, err := parseWholeAmount(oldBalance, "oldBalance")
	if err != nil {
		return MultiWithdrawalCircuitV1Input{}, err
	}

	var circuit MultiWithdrawalCircuitV1
	circuit.StateDomainField = fieldForLeafStringV1(stateRootDomainTagV1)
	circuit.NullifierDomainField = fieldForLeafStringV1(nullifiersRootDomainTagV1)
	circuit.OwnerField = ownerField
	circuit.SecretField = secretField
	circuit.OldBalance = oldBal

	total := new(big.Int)
	prevNonce := new(big.Int).SetInt64(-1)
	nullifierFields := make([]*big.Int, 0, maxWithdrawalsPerProof)

	for i := 0; i < maxWithdrawalsPerProof; i++ {
		if i < len(ops) {
			nonce, perr := parseNonNegativeDecimalForNullifier(ops[i].Nonce)
			if perr != nil {
				return MultiWithdrawalCircuitV1Input{}, fmt.Errorf("withdrawal %d nonce %q: %v", i, ops[i].Nonce, perr)
			}
			if nonce.Cmp(prevNonce) <= 0 {
				return MultiWithdrawalCircuitV1Input{}, fmt.Errorf("withdrawal %d nonce %s not strictly increasing", i, nonce)
			}
			prevNonce = nonce

			amount, perr := parseWholeAmount(ops[i].Amount, "amount")
			if perr != nil {
				return MultiWithdrawalCircuitV1Input{}, err
			}
			expected, nerr := NullifierCircuitV1ForFields(secretField, nonce)
			if nerr != nil {
				return MultiWithdrawalCircuitV1Input{}, nerr
			}

			circuit.Withdrawals[i] = withdrawalSlotVars{
				Active: 1, NonceField: nonce, Amount: amount, ExpectedNullifier: expected,
			}
			total.Add(total, amount)
			nullifierFields = append(nullifierFields, expected)
		} else {
			// no-op padding: inactive, nonce 0, amount 0, nullifier = MiMC(secret, 0).
			padNonce := big.NewInt(0)
			expected, nerr := NullifierCircuitV1ForFields(secretField, padNonce)
			if nerr != nil {
				return MultiWithdrawalCircuitV1Input{}, nerr
			}
			circuit.Withdrawals[i] = withdrawalSlotVars{
				Active: 0, NonceField: padNonce, Amount: big.NewInt(0), ExpectedNullifier: expected,
			}
			nullifierFields = append(nullifierFields, expected)
		}
	}

	newBal := new(big.Int).Sub(oldBal, total)
	if newBal.Sign() < 0 {
		return MultiWithdrawalCircuitV1Input{}, fmt.Errorf("total withdrawn %s exceeds oldBalance %s", total, oldBal)
	}
	circuit.NewBalance = newBal

	oldRoot := mimcFoldTriple(circuit.StateDomainField.(*big.Int), ownerField, oldBal)
	newRoot := mimcFoldTriple(circuit.StateDomainField.(*big.Int), ownerField, newBal)
	nullRoot := foldNullifiers(circuit.NullifierDomainField.(*big.Int), nullifierFields)
	circuit.OldStateRoot = oldRoot
	circuit.NewStateRoot = newRoot
	circuit.NullifiersRoot = nullRoot

	return MultiWithdrawalCircuitV1Input{
		circuit:        circuit,
		OldStateRoot:   "0x" + fieldBigIntToHex(oldRoot),
		NewStateRoot:   "0x" + fieldBigIntToHex(newRoot),
		NullifiersRoot: "0x" + fieldBigIntToHex(nullRoot),
	}, nil
}

func mimcFoldTriple(domain, owner, balance *big.Int) *big.Int {
	h := bn254mimc.NewMiMC()
	_, _ = h.Write(bigIntToBN254FieldBytes(domain))
	_, _ = h.Write(bigIntToBN254FieldBytes(owner))
	_, _ = h.Write(bigIntToBN254FieldBytes(balance))
	return bytesToBN254FieldBigInt(h.Sum(nil))
}

func foldNullifiers(domain *big.Int, nullifiers []*big.Int) *big.Int {
	h := bn254mimc.NewMiMC()
	_, _ = h.Write(bigIntToBN254FieldBytes(domain))
	for _, n := range nullifiers {
		_, _ = h.Write(bigIntToBN254FieldBytes(n))
	}
	return bytesToBN254FieldBigInt(h.Sum(nil))
}

func compileAndSetupMultiWithdrawalCircuit() (constraint.ConstraintSystem, groth16.ProvingKey, groth16.VerifyingKey, error) {
	var circuit MultiWithdrawalCircuitV1
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("compile multi-withdrawal circuit v1: %w", err)
	}
	provingKey, verifyingKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("setup multi-withdrawal circuit v1: %w", err)
	}
	return ccs, provingKey, verifyingKey, nil
}

// ProveMultiWithdrawalCircuitV1 proves one proof settling all the account's
// withdrawals. It fails on a wrong nullifier, out-of-order nonce, over-withdraw,
// or a tampered root.
func ProveMultiWithdrawalCircuitV1(input MultiWithdrawalCircuitV1Input) (string, error) {
	ccs, provingKey, _, err := compileAndSetupMultiWithdrawalCircuit()
	if err != nil {
		return "", err
	}

	witness, err := frontend.NewWitness(&input.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build multi-withdrawal witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove multi-withdrawal circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize multi-withdrawal proof: %w", err)
	}
	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

// proveMultiWithdrawalWithKeys proves using an already-compiled ccs + proving key
// (so benchmarks can measure prove time without the one-off compile/setup cost).
func proveMultiWithdrawalWithKeys(ccs constraint.ConstraintSystem, pk groth16.ProvingKey, input MultiWithdrawalCircuitV1Input) (groth16.Proof, error) {
	witness, err := frontend.NewWitness(&input.circuit, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("build multi-withdrawal witness: %w", err)
	}
	return groth16.Prove(ccs, pk, witness)
}

// TamperWithdrawalNullifier corrupts a slot's expected nullifier (keeping roots)
// so the per-withdrawal nullifier check fails.
func (in *MultiWithdrawalCircuitV1Input) TamperWithdrawalNullifier(slot int) {
	in.circuit.Withdrawals[slot].ExpectedNullifier = big.NewInt(987654321)
}

// ForceNonceField overwrites a slot's nonce to build an out-of-order witness that
// the circuit must reject (nonce ordering).
func (in *MultiWithdrawalCircuitV1Input) ForceNonceField(slot int, nonce int64) {
	in.circuit.Withdrawals[slot].NonceField = big.NewInt(nonce)
}
