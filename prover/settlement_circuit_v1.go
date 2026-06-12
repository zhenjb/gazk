package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdmimc "github.com/consensys/gnark/std/hash/mimc"

	"github.com/zhenjb/gazk/contract"
)

// SettlementCircuitV1 is the v1 combined settlement smoke circuit.
//
// It proves:
//
//  1. oldBalance + depositAmount == newBalance + withdrawAmount
//  2. expectedNullifier == MiMC(secretField, nonceField)
//  3. expectedDestinationHash == MiMC(destinationField)
//
// Current limitation:
// - supports the current single-account/single-withdrawal Alice vector.
// - state roots and commitment roots remain external public input checks.
type SettlementCircuitV1 struct {
	OldBalance     frontend.Variable
	DepositAmount  frontend.Variable
	WithdrawAmount frontend.Variable
	NewBalance     frontend.Variable

	SecretField       frontend.Variable
	NonceField        frontend.Variable
	ExpectedNullifier frontend.Variable `gnark:",public"`

	DestinationField        frontend.Variable
	ExpectedDestinationHash frontend.Variable `gnark:",public"`
}

func (c *SettlementCircuitV1) Define(api frontend.API) error {
	left := api.Add(c.OldBalance, c.DepositAmount)
	right := api.Add(c.NewBalance, c.WithdrawAmount)
	api.AssertIsEqual(left, right)

	nullifierHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}

	nullifierHasher.Write(c.SecretField, c.NonceField)
	computedNullifier := nullifierHasher.Sum()
	api.AssertIsEqual(computedNullifier, c.ExpectedNullifier)

	destinationHasher, err := stdmimc.NewMiMC(api)
	if err != nil {
		return err
	}

	destinationHasher.Write(c.DestinationField)
	computedDestinationHash := destinationHasher.Sum()
	api.AssertIsEqual(computedDestinationHash, c.ExpectedDestinationHash)

	return nil
}

type SettlementCircuitV1Engine struct {
	ccs        constraint.ConstraintSystem
	provingKey groth16.ProvingKey
	verifyKey  groth16.VerifyingKey
}

func NewSettlementCircuitV1Engine() (*SettlementCircuitV1Engine, error) {
	var circuit SettlementCircuitV1

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compile settlement circuit v1: %w", err)
	}

	provingKey, verifyKey, err := groth16.Setup(ccs)
	if err != nil {
		return nil, fmt.Errorf("setup settlement circuit v1: %w", err)
	}

	return &SettlementCircuitV1Engine{
		ccs:        ccs,
		provingKey: provingKey,
		verifyKey:  verifyKey,
	}, nil
}

type settlementCircuitV1Input struct {
	OldBalance     *big.Int
	DepositAmount  *big.Int
	WithdrawAmount *big.Int
	NewBalance     *big.Int

	SecretField       *big.Int
	NonceField        *big.Int
	ExpectedNullifier *big.Int

	DestinationField        *big.Int
	ExpectedDestinationHash *big.Int

	Owner              string
	BoundWithdrawalID  string
	BoundWithdrawalIdx int
}

func buildSettlementCircuitV1Input(req contract.ProveRequest) (settlementCircuitV1Input, error) {
	balanceInput, err := buildBalanceTransitionInput(req)
	if err != nil {
		return settlementCircuitV1Input{}, err
	}

	if len(req.Witness.Accounts) != 1 {
		return settlementCircuitV1Input{}, fmt.Errorf(
			"%w: settlement circuit v1 currently supports exactly one witness account, got %d",
			ErrInvalidProveRequest,
			len(req.Witness.Accounts),
		)
	}

	account := req.Witness.Accounts[0]
	owner := strings.TrimSpace(account.Owner)
	if owner == "" {
		return settlementCircuitV1Input{}, fmt.Errorf("%w: witness.accounts[0].owner is required", ErrInvalidProveRequest)
	}

	secretField, err := SecretFieldForV1(account.UserSecret)
	if err != nil {
		return settlementCircuitV1Input{}, fmt.Errorf("%w: secretField derivation: %v", ErrInvalidProveRequest, err)
	}

	nonceField, err := parseNonNegativeDecimalForNullifier(account.Nonce)
	if err != nil {
		return settlementCircuitV1Input{}, fmt.Errorf("%w: nonce %q invalid: %v", ErrInvalidProveRequest, account.Nonce, err)
	}

	withdrawalIndex := -1
	var withdrawal contract.SettlementWithdrawal

	for i, candidate := range req.SettlementUpdate.Withdrawals {
		if strings.TrimSpace(candidate.Owner) != owner {
			continue
		}

		if withdrawalIndex != -1 {
			return settlementCircuitV1Input{}, fmt.Errorf(
				"%w: settlement circuit v1 currently supports exactly one withdrawal for owner %q",
				ErrInvalidProveRequest,
				owner,
			)
		}

		withdrawalIndex = i
		withdrawal = candidate
	}

	if withdrawalIndex == -1 {
		return settlementCircuitV1Input{}, fmt.Errorf(
			"%w: settlement circuit v1 requires one withdrawal for owner %q",
			ErrInvalidProveRequest,
			owner,
		)
	}

	expectedNullifier, err := parse0xFieldBigInt(
		withdrawal.Nullifier,
		fmt.Sprintf("settlementUpdate.withdrawals[%d].nullifier", withdrawalIndex),
	)
	if err != nil {
		return settlementCircuitV1Input{}, err
	}

	destinationField, err := DestinationFieldForV1(withdrawal.Destination)
	if err != nil {
		return settlementCircuitV1Input{}, fmt.Errorf(
			"%w: settlementUpdate.withdrawals[%d] destinationField derivation: %v",
			ErrInvalidProveRequest,
			withdrawalIndex,
			err,
		)
	}

	expectedDestinationHash, err := parse0xFieldBigInt(
		withdrawal.DestinationHash,
		fmt.Sprintf("settlementUpdate.withdrawals[%d].destinationHash", withdrawalIndex),
	)
	if err != nil {
		return settlementCircuitV1Input{}, err
	}

	return settlementCircuitV1Input{
		OldBalance:     balanceInput.OldBalance,
		DepositAmount:  balanceInput.DepositAmount,
		WithdrawAmount: balanceInput.WithdrawAmount,
		NewBalance:     balanceInput.NewBalance,

		SecretField:       secretField,
		NonceField:        nonceField,
		ExpectedNullifier: expectedNullifier,

		DestinationField:        destinationField,
		ExpectedDestinationHash: expectedDestinationHash,

		Owner:              owner,
		BoundWithdrawalID:  withdrawal.WithdrawID,
		BoundWithdrawalIdx: withdrawalIndex,
	}, nil
}

func (e *SettlementCircuitV1Engine) BuildProof(req contract.ProveRequest) (string, error) {
	input, err := buildSettlementCircuitV1Input(req)
	if err != nil {
		return "", err
	}

	assignment := SettlementCircuitV1{
		OldBalance:     input.OldBalance,
		DepositAmount:  input.DepositAmount,
		WithdrawAmount: input.WithdrawAmount,
		NewBalance:     input.NewBalance,

		SecretField:       input.SecretField,
		NonceField:        input.NonceField,
		ExpectedNullifier: input.ExpectedNullifier,

		DestinationField:        input.DestinationField,
		ExpectedDestinationHash: input.ExpectedDestinationHash,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build settlement circuit v1 witness: %w", err)
	}

	proof, err := groth16.Prove(e.ccs, e.provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove settlement circuit v1: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize settlement circuit v1 proof: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

func (e *SettlementCircuitV1Engine) VerifyProof(req contract.VerifyRequest) error {
	publicInputs, err := expectedSettlementCircuitV1PublicInputs(req.SettlementUpdate)
	if err != nil {
		return err
	}

	proofBytes, err := decodeProofHex(req.ProofBundle.Proof)
	if err != nil {
		return err
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("%w: cannot deserialize Groth16 proof: %v", ErrInvalidProofBundle, err)
	}

	publicAssignment := SettlementCircuitV1{
		ExpectedNullifier:       publicInputs.ExpectedNullifier,
		ExpectedDestinationHash: publicInputs.ExpectedDestinationHash,
	}

	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build settlement circuit v1 public witness: %w", err)
	}

	if err := groth16.Verify(proof, e.verifyKey, publicWitness); err != nil {
		return fmt.Errorf("%w: Groth16 settlement v1 verification failed: %v", ErrInvalidProofBundle, err)
	}

	return nil
}

type settlementCircuitV1PublicInputs struct {
	ExpectedNullifier       *big.Int
	ExpectedDestinationHash *big.Int
}

func expectedSettlementCircuitV1PublicInputs(update contract.SettlementUpdate) (settlementCircuitV1PublicInputs, error) {
	if len(update.Withdrawals) != 1 {
		return settlementCircuitV1PublicInputs{}, fmt.Errorf(
			"%w: settlement circuit v1 verification currently expects exactly one withdrawal, got %d",
			ErrInvalidProofBundle,
			len(update.Withdrawals),
		)
	}

	expectedNullifier, err := parse0xFieldBigInt(update.Withdrawals[0].Nullifier, "settlementUpdate.withdrawals[0].nullifier")
	if err != nil {
		return settlementCircuitV1PublicInputs{}, err
	}

	expectedDestinationHash, err := parse0xFieldBigInt(update.Withdrawals[0].DestinationHash, "settlementUpdate.withdrawals[0].destinationHash")
	if err != nil {
		return settlementCircuitV1PublicInputs{}, err
	}

	return settlementCircuitV1PublicInputs{
		ExpectedNullifier:       expectedNullifier,
		ExpectedDestinationHash: expectedDestinationHash,
	}, nil
}

func decodeProofHex(proofHex string) ([]byte, error) {
	raw := strings.TrimSpace(proofHex)
	if raw == "" {
		return nil, fmt.Errorf("%w: proof is empty", ErrInvalidProofBundle)
	}

	if !strings.HasPrefix(raw, "0x") {
		return nil, fmt.Errorf("%w: proof must have 0x prefix", ErrInvalidProofBundle)
	}

	proofBytes, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return nil, fmt.Errorf("%w: proof is not valid hex: %v", ErrInvalidProofBundle, err)
	}

	return proofBytes, nil
}

func parse0xFieldBigInt(value string, field string) (*big.Int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidProveRequest, field)
	}

	if !strings.HasPrefix(raw, "0x") {
		return nil, fmt.Errorf("%w: %s must have 0x prefix", ErrInvalidProveRequest, field)
	}

	decoded, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return nil, fmt.Errorf("%w: %s must be valid hex: %v", ErrInvalidProveRequest, field, err)
	}

	if len(decoded) == 0 {
		return nil, fmt.Errorf("%w: %s must not be empty hex", ErrInvalidProveRequest, field)
	}

	return bytesToBN254FieldBigInt(decoded), nil
}
