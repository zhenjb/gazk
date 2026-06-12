package prover

import (
	"fmt"
	"strings"

	"github.com/zhenjb/gazk/contract"
)

func validateNullifierBindingV1(req contract.ProveRequest) error {
	if len(req.Witness.Accounts) == 0 {
		return fmt.Errorf("%w: witness.accounts is required", ErrInvalidProveRequest)
	}

	nonces := make(map[string]string, len(req.Witness.Accounts))
	secrets := make(map[string]string, len(req.Witness.Accounts))

	for i, account := range req.Witness.Accounts {
		owner := strings.TrimSpace(account.Owner)
		if owner == "" {
			return fmt.Errorf("%w: witness.accounts[%d].owner is required", ErrInvalidProveRequest, i)
		}

		secret := strings.TrimSpace(account.UserSecret)
		if secret == "" {
			return fmt.Errorf("%w: witness.accounts[%d].userSecret is required", ErrInvalidProveRequest, i)
		}

		nonce := strings.TrimSpace(account.Nonce)
		if nonce == "" {
			return fmt.Errorf("%w: witness.accounts[%d].nonce is required", ErrInvalidProveRequest, i)
		}

		if _, exists := nonces[owner]; exists {
			return fmt.Errorf("%w: duplicate witness account owner %q", ErrInvalidProveRequest, owner)
		}

		secrets[owner] = secret
		nonces[owner] = nonce
	}

	for i, withdrawal := range req.SettlementUpdate.Withdrawals {
		owner := strings.TrimSpace(withdrawal.Owner)
		if owner == "" {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d].owner is required", ErrInvalidProveRequest, i)
		}

		secret, ok := secrets[owner]
		if !ok {
			return fmt.Errorf(
				"%w: settlementUpdate.withdrawals[%d].owner %q has no witness account",
				ErrInvalidProveRequest,
				i,
				owner,
			)
		}

		expected, err := NullifierCircuitV1Hex(secret, nonces[owner])
		if err != nil {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d] v1 circuit nullifier derivation: %v", ErrInvalidProveRequest, i, err)
		}

		if withdrawal.Nullifier != expected {
			return fmt.Errorf(
				"%w: settlementUpdate.withdrawals[%d].nullifier v1 circuit mismatch: got %q, expected %q",
				ErrInvalidProveRequest,
				i,
				withdrawal.Nullifier,
				expected,
			)
		}
	}

	return nil
}

func validateDestinationHashBindingV1(req contract.ProveRequest) error {
	for i, withdrawal := range req.SettlementUpdate.Withdrawals {
		destination := strings.TrimSpace(withdrawal.Destination)
		if destination == "" {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d].destination is required", ErrInvalidProveRequest, i)
		}

		expected, err := DestinationHashCircuitV1Hex(destination)
		if err != nil {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d] v1 circuit destinationHash derivation: %v", ErrInvalidProveRequest, i, err)
		}

		if withdrawal.DestinationHash != expected {
			return fmt.Errorf(
				"%w: settlementUpdate.withdrawals[%d].destinationHash v1 circuit mismatch: got %q, expected %q",
				ErrInvalidProveRequest,
				i,
				withdrawal.DestinationHash,
				expected,
			)
		}
	}

	return nil
}
