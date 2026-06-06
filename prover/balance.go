package prover

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/zhenjb/gazk/contract"
)

// BalanceTransitionCircuit is the first settlement-aware smoke circuit.
//
// Constraint:
//
//	oldBalance + depositAmount == newBalance + withdrawAmount
//
// For the canonical Alice vector:
//
//	0 + 100 == 60 + 40
//
// This is not the final settlement circuit yet. It is the first real gnark
// constraint that moves gazk beyond hash-only smoke proof generation.
type BalanceTransitionCircuit struct {
	OldBalance     frontend.Variable
	DepositAmount  frontend.Variable
	WithdrawAmount frontend.Variable

	// NewBalance is public only for this smoke circuit.
	// The external GANC ProofBundle publicInputs remain the 6 settlement roots.
	NewBalance frontend.Variable `gnark:",public"`
}

func (c *BalanceTransitionCircuit) Define(api frontend.API) error {
	left := api.Add(c.OldBalance, c.DepositAmount)
	right := api.Add(c.NewBalance, c.WithdrawAmount)

	api.AssertIsEqual(left, right)
	return nil
}

type balanceTransitionInput struct {
	OldBalance     *big.Int
	DepositAmount  *big.Int
	WithdrawAmount *big.Int
	NewBalance     *big.Int
}

func buildBalanceTransitionInput(req contract.ProveRequest) (balanceTransitionInput, error) {
	if len(req.Witness.Accounts) == 0 {
		return balanceTransitionInput{}, fmt.Errorf("%w: witness.accounts is required", ErrInvalidProveRequest)
	}

	account := req.Witness.Accounts[0]
	owner := strings.TrimSpace(account.Owner)
	if owner == "" {
		return balanceTransitionInput{}, fmt.Errorf("%w: witness.accounts[0].owner is required", ErrInvalidProveRequest)
	}

	oldBalance, err := parseNonNegativeDecimal(account.OldBalance, "witness.accounts[0].oldBalance")
	if err != nil {
		return balanceTransitionInput{}, err
	}

	newBalance, err := parseNonNegativeDecimal(account.NewBalance, "witness.accounts[0].newBalance")
	if err != nil {
		return balanceTransitionInput{}, err
	}

	depositAmount := new(big.Int)
	for i, deposit := range req.SettlementUpdate.Deposits {
		if deposit.Owner != owner {
			continue
		}

		amount, err := parseNonNegativeDecimal(
			deposit.Amount,
			fmt.Sprintf("settlementUpdate.deposits[%d].amount", i),
		)
		if err != nil {
			return balanceTransitionInput{}, err
		}

		depositAmount.Add(depositAmount, amount)
	}

	withdrawAmount := new(big.Int)
	for i, withdrawal := range req.SettlementUpdate.Withdrawals {
		if withdrawal.Owner != owner {
			continue
		}

		amount, err := parseNonNegativeDecimal(
			withdrawal.Amount,
			fmt.Sprintf("settlementUpdate.withdrawals[%d].amount", i),
		)
		if err != nil {
			return balanceTransitionInput{}, err
		}

		withdrawAmount.Add(withdrawAmount, amount)
	}

	left := new(big.Int).Add(oldBalance, depositAmount)
	right := new(big.Int).Add(newBalance, withdrawAmount)

	if left.Cmp(right) != 0 {
		return balanceTransitionInput{}, fmt.Errorf(
			"%w: balance transition violated: oldBalance(%s)+depositAmount(%s)=%s != newBalance(%s)+withdrawAmount(%s)=%s",
			ErrInvalidProveRequest,
			oldBalance.String(),
			depositAmount.String(),
			left.String(),
			newBalance.String(),
			withdrawAmount.String(),
			right.String(),
		)
	}

	return balanceTransitionInput{
		OldBalance:     oldBalance,
		DepositAmount:  depositAmount,
		WithdrawAmount: withdrawAmount,
		NewBalance:     newBalance,
	}, nil
}

func buildBalanceTransitionProof(req contract.ProveRequest) (string, error) {
	input, err := buildBalanceTransitionInput(req)
	if err != nil {
		return "", err
	}

	var circuit BalanceTransitionCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return "", fmt.Errorf("compile balance transition circuit: %w", err)
	}

	provingKey, _, err := groth16.Setup(ccs)
	if err != nil {
		return "", fmt.Errorf("setup balance transition circuit: %w", err)
	}

	assignment := BalanceTransitionCircuit{
		OldBalance:     input.OldBalance,
		DepositAmount:  input.DepositAmount,
		WithdrawAmount: input.WithdrawAmount,
		NewBalance:     input.NewBalance,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return "", fmt.Errorf("build balance transition witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove balance transition: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize balance transition proof: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

func parseNonNegativeDecimal(value string, field string) (*big.Int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, fmt.Errorf("%w: %s is required", ErrInvalidProveRequest, field)
	}

	out, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return nil, fmt.Errorf("%w: %s must be a base-10 integer", ErrInvalidProveRequest, field)
	}

	if out.Sign() < 0 {
		return nil, fmt.Errorf("%w: %s must be non-negative", ErrInvalidProveRequest, field)
	}

	return out, nil
}
