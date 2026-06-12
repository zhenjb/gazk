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
// Current smoke design:
//   - all circuit variables are private;
//   - the external GANC ProofBundle still carries the 6 settlement public inputs;
//   - /verify checks those 6 public inputs at service level, then verifies the
//     Groth16 proof against an empty gnark public witness.
//
// Later versions will bind the 6 settlement public inputs inside the circuit.
type BalanceTransitionCircuit struct {
	OldBalance     frontend.Variable
	DepositAmount  frontend.Variable
	WithdrawAmount frontend.Variable
	NewBalance     frontend.Variable
}

func (c *BalanceTransitionCircuit) Define(api frontend.API) error {
	left := api.Add(c.OldBalance, c.DepositAmount)
	right := api.Add(c.NewBalance, c.WithdrawAmount)

	api.AssertIsEqual(left, right)
	return nil
}

type BalanceTransitionEngine struct {
	ccs        constraint.ConstraintSystem
	provingKey groth16.ProvingKey
	verifyKey  groth16.VerifyingKey
}

func NewBalanceTransitionEngine() (*BalanceTransitionEngine, error) {
	var circuit BalanceTransitionCircuit

	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		return nil, fmt.Errorf("compile balance transition circuit: %w", err)
	}

	provingKey, verifyKey, err := loadOrSetupGroth16Keys(ccs, configuredKeyDir(), VerificationKeyID)
	if err != nil {
		return nil, fmt.Errorf("load/setup balance transition circuit keys: %w", err)
	}

	return &BalanceTransitionEngine{
		ccs:        ccs,
		provingKey: provingKey,
		verifyKey:  verifyKey,
	}, nil
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

func (e *BalanceTransitionEngine) BuildProof(req contract.ProveRequest) (string, error) {
	input, err := buildBalanceTransitionInput(req)
	if err != nil {
		return "", err
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

	proof, err := groth16.Prove(e.ccs, e.provingKey, witness)
	if err != nil {
		return "", fmt.Errorf("prove balance transition: %w", err)
	}

	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return "", fmt.Errorf("serialize balance transition proof: %w", err)
	}

	return "0x" + hex.EncodeToString(buf.Bytes()), nil
}

func (e *BalanceTransitionEngine) VerifyProof(proofHex string) error {
	raw := strings.TrimSpace(proofHex)
	if raw == "" {
		return fmt.Errorf("%w: proof is empty", ErrInvalidProofBundle)
	}

	if !strings.HasPrefix(raw, "0x") {
		return fmt.Errorf("%w: proof must have 0x prefix", ErrInvalidProofBundle)
	}

	proofBytes, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
	if err != nil {
		return fmt.Errorf("%w: proof is not valid hex: %v", ErrInvalidProofBundle, err)
	}

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return fmt.Errorf("%w: cannot deserialize Groth16 proof: %v", ErrInvalidProofBundle, err)
	}

	var publicAssignment BalanceTransitionCircuit
	publicWitness, err := frontend.NewWitness(&publicAssignment, ecc.BN254.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return fmt.Errorf("build balance transition public witness: %w", err)
	}

	if err := groth16.Verify(proof, e.verifyKey, publicWitness); err != nil {
		return fmt.Errorf("%w: Groth16 verification failed: %v", ErrInvalidProofBundle, err)
	}

	return nil
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
