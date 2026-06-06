package prover

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/zhenjb/gazk/contract"
)

const NullifierDomainTag = "zkdex/nullifier/v0"

func validateNullifierBinding(req contract.ProveRequest) error {
	if len(req.Witness.Accounts) == 0 {
		return fmt.Errorf("%w: witness.accounts is required", ErrInvalidProveRequest)
	}

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

		if _, exists := secrets[owner]; exists {
			return fmt.Errorf("%w: duplicate witness account owner %q", ErrInvalidProveRequest, owner)
		}

		secrets[owner] = secret
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

		nonce, err := nonceForOwner(req.Witness, owner)
		if err != nil {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d].owner %q nonce lookup: %v", ErrInvalidProveRequest, i, owner, err)
		}

		expected, err := NullifierFor(secret, nonce)
		if err != nil {
			return fmt.Errorf("%w: settlementUpdate.withdrawals[%d] nullifier derivation: %v", ErrInvalidProveRequest, i, err)
		}

		if withdrawal.Nullifier != expected {
			return fmt.Errorf(
				"%w: settlementUpdate.withdrawals[%d].nullifier mismatch: got %q, expected %q",
				ErrInvalidProveRequest,
				i,
				withdrawal.Nullifier,
				expected,
			)
		}
	}

	return nil
}

func nonceForOwner(witness contract.Witness, owner string) (string, error) {
	for _, account := range witness.Accounts {
		if strings.TrimSpace(account.Owner) == owner {
			return account.Nonce, nil
		}
	}

	return "", fmt.Errorf("owner not found")
}

func NullifierFor(userSecret string, nonce string) (string, error) {
	userSecret = strings.TrimSpace(userSecret)
	if userSecret == "" {
		return "", fmt.Errorf("userSecret is empty")
	}

	parsedNonce, err := parseNonNegativeDecimalForNullifier(nonce)
	if err != nil {
		return "", fmt.Errorf("nonce %q invalid: %v", nonce, err)
	}

	canonicalNonce := parsedNonce.String()

	payload := NullifierDomainTag + "|" + userSecret + "|" + canonicalNonce
	sum := sha256.Sum256([]byte(payload))

	return "0x" + hex.EncodeToString(sum[:]), nil
}

func parseNonNegativeDecimalForNullifier(value string) (*big.Int, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return nil, fmt.Errorf("empty")
	}

	out, ok := new(big.Int).SetString(raw, 10)
	if !ok {
		return nil, fmt.Errorf("not a base-10 integer")
	}

	if out.Sign() < 0 {
		return nil, fmt.Errorf("negative")
	}

	return out, nil
}
