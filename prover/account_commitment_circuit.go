package prover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	bn254mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"
)

// AccountCommitmentCircuitV1 is the D5-A field-native account commitment prototype.
//
// It proves:
//
//  1. oldBalance + depositAmount == newBalance + withdrawAmount
//  2. oldAccountCommitment == MiMC(ownerField, oldBalance)
//  3. newAccountCommitment == MiMC(ownerField, newBalance)
//
// This is intentionally NOT wired into /prove yet.
//
// Important:
// - owner string hashing is not done inside the circuit.
// - service/preprocessing maps owner -> ownerField.
// - this is not a Merkle root circuit yet.
type AccountCommitmentCircuitV1 struct {
	OwnerField     frontend.Variable
	OldBalance     frontend.Variable
	DepositAmount  frontend.Variable
	WithdrawAmount frontend.Variable
	NewBalance     frontend.Variable

	OldAccountCommitment frontend.Variable `gnark:",public"`
	NewAccountCommitment frontend.Variable `gnark:",public"`
}

func (c *AccountCommitmentCircuitV1) Define(api frontend.API) error {
	left := api.Add(c.OldBalance, c.DepositAmount)
	right := api.Add(c.NewBalance, c.WithdrawAmount)
	api.AssertIsEqual(left, right)

	oldHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	oldHasher.Write(c.OwnerField, c.OldBalance)
	computedOldCommitment := oldHasher.Sum()
	api.AssertIsEqual(computedOldCommitment, c.OldAccountCommitment)

	newHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}
	newHasher.Write(c.OwnerField, c.NewBalance)
	computedNewCommitment := newHasher.Sum()
	api.AssertIsEqual(computedNewCommitment, c.NewAccountCommitment)

	return nil
}

type AccountCommitmentCircuitV1Input struct {
	OwnerField     *big.Int
	OldBalance     *big.Int
	DepositAmount  *big.Int
	WithdrawAmount *big.Int
	NewBalance     *big.Int

	OldAccountCommitment *big.Int
	NewAccountCommitment *big.Int
}

func BuildAccountCommitmentCircuitV1Input(
	owner string,
	oldBalance string,
	depositAmount string,
	withdrawAmount string,
	newBalance string,
) (AccountCommitmentCircuitV1Input, error) {
	ownerField, err := OwnerFieldForV1(owner)
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, err
	}

	oldBalanceValue, err := parseNonNegativeDecimal(oldBalance, "oldBalance")
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, err
	}

	depositAmountValue, err := parseNonNegativeDecimal(depositAmount, "depositAmount")
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, err
	}

	withdrawAmountValue, err := parseNonNegativeDecimal(withdrawAmount, "withdrawAmount")
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, err
	}

	newBalanceValue, err := parseNonNegativeDecimal(newBalance, "newBalance")
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, err
	}

	left := new(big.Int).Add(oldBalanceValue, depositAmountValue)
	right := new(big.Int).Add(newBalanceValue, withdrawAmountValue)

	if left.Cmp(right) != 0 {
		return AccountCommitmentCircuitV1Input{}, fmt.Errorf(
			"%w: balance transition violated: oldBalance(%s)+depositAmount(%s)=%s != newBalance(%s)+withdrawAmount(%s)=%s",
			ErrInvalidProveRequest,
			oldBalanceValue.String(),
			depositAmountValue.String(),
			left.String(),
			newBalanceValue.String(),
			withdrawAmountValue.String(),
			right.String(),
		)
	}

	oldCommitment, err := AccountCommitmentCircuitV1ForField(ownerField, oldBalanceValue)
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, fmt.Errorf("derive old account commitment: %w", err)
	}

	newCommitment, err := AccountCommitmentCircuitV1ForField(ownerField, newBalanceValue)
	if err != nil {
		return AccountCommitmentCircuitV1Input{}, fmt.Errorf("derive new account commitment: %w", err)
	}

	return AccountCommitmentCircuitV1Input{
		OwnerField:           ownerField,
		OldBalance:           oldBalanceValue,
		DepositAmount:        depositAmountValue,
		WithdrawAmount:       withdrawAmountValue,
		NewBalance:           newBalanceValue,
		OldAccountCommitment: oldCommitment,
		NewAccountCommitment: newCommitment,
	}, nil
}

// OwnerFieldForV1 maps an opaque account owner string into a BN254 scalar field
// element outside the circuit.
//
// This is a preprocessing helper for D5-A. It deliberately keeps arbitrary
// string handling outside the circuit.
func OwnerFieldForV1(owner string) (*big.Int, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return nil, fmt.Errorf("owner is empty")
	}

	digest := sha256.Sum256([]byte("zkdex/ownerField/v1|" + owner))
	return bytesToBN254FieldBigInt(digest[:]), nil
}

// AccountCommitmentCircuitV1ForField computes the native-field account
// commitment used by AccountCommitmentCircuitV1.
//
// It must match the circuit expression:
//
//	MiMC(ownerField, balance)
func AccountCommitmentCircuitV1ForField(ownerField *big.Int, balance *big.Int) (*big.Int, error) {
	if ownerField == nil {
		return nil, fmt.Errorf("ownerField is nil")
	}

	if balance == nil {
		return nil, fmt.Errorf("balance is nil")
	}

	if ownerField.Sign() < 0 {
		return nil, fmt.Errorf("ownerField must be non-negative")
	}

	if balance.Sign() < 0 {
		return nil, fmt.Errorf("balance must be non-negative")
	}

	h := bn254mimc.NewMiMC()

	if _, err := h.Write(bigIntToBN254FieldBytes(ownerField)); err != nil {
		return nil, fmt.Errorf("write owner field: %w", err)
	}

	if _, err := h.Write(bigIntToBN254FieldBytes(balance)); err != nil {
		return nil, fmt.Errorf("write balance field: %w", err)
	}

	return bytesToBN254FieldBigInt(h.Sum(nil)), nil
}

func AccountCommitmentCircuitV1Hex(owner string, balance string) (string, error) {
	ownerField, err := OwnerFieldForV1(owner)
	if err != nil {
		return "", err
	}

	balanceValue, err := parseNonNegativeDecimal(balance, "balance")
	if err != nil {
		return "", err
	}

	commitment, err := AccountCommitmentCircuitV1ForField(ownerField, balanceValue)
	if err != nil {
		return "", err
	}

	return "0x" + fieldBigIntToHex(commitment), nil
}

func ProveAccountCommitmentCircuitV1(input AccountCommitmentCircuitV1Input) (string, error) {
	var circuit AccountCommitmentCircuitV1

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return "", fmt.Errorf("compile account commitment circuit v1: %w", err)
	}

	provingKey, _, err := groth16.Setup(ccs)
	if err != nil {
		return "", fmt.Errorf("setup account commitment circuit v1: %w", err)
	}

	assignment := AccountCommitmentCircuitV1{
		OwnerField:           input.OwnerField,
		OldBalance:           input.OldBalance,
		DepositAmount:        input.DepositAmount,
		WithdrawAmount:       input.WithdrawAmount,
		NewBalance:           input.NewBalance,
		OldAccountCommitment: input.OldAccountCommitment,
		NewAccountCommitment: input.NewAccountCommitment,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build account commitment circuit v1 witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove account commitment circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize account commitment circuit v1 proof: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}
