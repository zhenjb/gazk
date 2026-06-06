package prover

import (
	"fmt"
	"strings"

	"github.com/zhenjb/gazk/contract"
)

func validateSettlementPublicFields(
	update contract.SettlementUpdate,
	commitments contract.BatchCommitments,
) error {
	checks := []struct {
		name  string
		value string
	}{
		{name: "settlementUpdate.oldStateRoot", value: update.OldStateRoot},
		{name: "settlementUpdate.newStateRoot", value: update.NewStateRoot},
		{name: "batchCommitments.depositsRoot", value: commitments.DepositsRoot},
		{name: "batchCommitments.withdrawalsRoot", value: commitments.WithdrawalsRoot},
		{name: "batchCommitments.nullifiersRoot", value: commitments.NullifiersRoot},
		{name: "batchCommitments.withdrawOutputsRoot", value: commitments.WithdrawOutputsRoot},
	}

	for _, check := range checks {
		if err := validateExternalPublicInputField(check.name, check.value); err != nil {
			return err
		}
	}

	return nil
}

func validateExternalPublicInputField(name string, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalidProveRequest, name)
	}

	if !strings.HasPrefix(value, "0x") {
		return fmt.Errorf("%w: %s must have 0x prefix", ErrInvalidProveRequest, name)
	}

	if value == "0x" {
		return fmt.Errorf("%w: %s must not be empty hex", ErrInvalidProveRequest, name)
	}

	return nil
}

func validateProofBundlePublicInputs(publicInputs []string) error {
	if len(publicInputs) != 6 {
		return fmt.Errorf("%w: publicInputs must contain 6 values", ErrInvalidProofBundle)
	}

	for i, value := range publicInputs {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("%w: publicInputs[%d] is empty", ErrInvalidProofBundle, i)
		}

		if !strings.HasPrefix(value, "0x") {
			return fmt.Errorf("%w: publicInputs[%d] must have 0x prefix", ErrInvalidProofBundle, i)
		}

		if value == "0x" {
			return fmt.Errorf("%w: publicInputs[%d] must not be empty hex", ErrInvalidProofBundle, i)
		}
	}

	return nil
}
